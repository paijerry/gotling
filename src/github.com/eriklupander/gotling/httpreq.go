/**
The MIT License (MIT)

Copyright (c) 2015 ErikL

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	//"fmt"

	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"

	"github.com/NodePrime/jsonpath"
	"github.com/paijerry/gotools/wtfhash"
)

// Accepts a Httpaction and a one-way channel to write the results to.
func DoHttpRequest(httpAction HttpAction, resultsChannel chan HttpReqResult, sessionMap map[string]string) {
	req := buildHttpRequest(httpAction, sessionMap)

	start := time.Now()
	var DefaultTransport http.RoundTripper = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	resp, err := DefaultTransport.RoundTrip(req)

	if err != nil {
		log.Printf("HTTP request failed: %s", err)
	} else {
		elapsed := time.Since(start)
		responseBody, err := ioutil.ReadAll(resp.Body)

		writeLog(responseBody, httpAction.Title+" : "+sessionMap["id"])
		fmt.Printf("\n%+v(\x1b[32;1mrspn\x1b[0m) id=%+v: %+v", httpAction.Title, sessionMap["id"], string(responseBody))
		if err != nil {
			//log.Fatal(err)
			log.Printf("Reading HTTP response failed: %s\n", err)
			httpReqResult := buildHttpResult(0, resp.StatusCode, elapsed.Nanoseconds(), httpAction.Title)

			resultsChannel <- httpReqResult
		} else {
			defer resp.Body.Close()

			if httpAction.StoreCookie != "" {
				for _, cookie := range resp.Cookies() {

					if cookie.Name == httpAction.StoreCookie {
						sessionMap["____"+cookie.Name] = cookie.Value
					}
				}
			}

			// if action specifies response action, parse using regexp/jsonpath
			processResult(httpAction, sessionMap, responseBody)

			httpReqResult := buildHttpResult(len(responseBody), resp.StatusCode, elapsed.Nanoseconds(), httpAction.Title)

			resultsChannel <- httpReqResult
		}
	}
}

func buildHttpResult(contentLength int, status int, elapsed int64, title string) HttpReqResult {
	httpReqResult := HttpReqResult{
		"HTTP",
		elapsed,
		contentLength,
		status,
		title,
		time.Since(SimulationStart).Nanoseconds(),
	}
	return httpReqResult
}

func buildHttpRequest(httpAction HttpAction, sessionMap map[string]string) *http.Request {
	var req *http.Request
	var err error
	if httpAction.Body != "" {
		//reader := bytes.NewBuffer([]byte(SubstParams(sessionMap, httpAction.Body)))
		reqBodyStr := SubstParams(sessionMap, httpAction.Body)
		reqBodyStr = wtfHash(reqBodyStr)

		reader := strings.NewReader(reqBodyStr)
		req, err = http.NewRequest(httpAction.Method, SubstParams(sessionMap, httpAction.Url), reader)
		fmt.Printf("\n%+v(\x1b[31;1mreq\x1b[0m) id=%+v: %+v %+v", httpAction.Title, sessionMap["id"], reqBodyStr, sessionMap["UID"])

	} else if httpAction.Template != "" {
		reader := strings.NewReader(SubstParams(sessionMap, httpAction.Template))
		req, err = http.NewRequest(httpAction.Method, SubstParams(sessionMap, httpAction.Url), reader)
	} else {
		req, err = http.NewRequest(httpAction.Method, SubstParams(sessionMap, httpAction.Url), nil)
	}
	if err != nil {
		log.Fatal(err)
	}

	// Add headers
	req.Header.Add("Accept", httpAction.Accept)
	if httpAction.ContentType != "" {
		req.Header.Add("Content-Type", httpAction.ContentType)
	}
	// 自訂entry header
	if httpAction.Title == "Entry Auth" {
		t := time.Now().Unix()
		timestamp := strconv.FormatInt(t, 10)
		merchantkey := HmacSha256Encode(timestamp, httpAction.SecretKey)
		req.Header.Add("merchantname", httpAction.MerchantName)
		req.Header.Add("timestamp", timestamp)
		req.Header.Add("merchantkey", merchantkey)
	}

	// Add cookies stored by subsequent requests in the sessionMap having the kludgy ____ prefix
	for key, value := range sessionMap {
		if strings.HasPrefix(key, "____") {

			cookie := http.Cookie{
				Name:  key[4:len(key)],
				Value: value,
			}

			req.AddCookie(&cookie)
		}
	}
	return req
}

/**
 * If the httpAction specifies a Jsonpath in the Response, try to extract value(s)
 * from the responseBody.
 *
 * TODO extract both Jsonpath handling and Xmlpath handling into separate functions, and write tests for them.
 *
 * Uses github.com/NodePrime/jsonpath
 */
func processResult(httpAction HttpAction, sessionMap map[string]string, responseBody []byte) {
	if httpAction.ResponseHandler.Jsonpath != "" {
		paths, err := jsonpath.ParsePaths(httpAction.ResponseHandler.Jsonpath)
		if err != nil {
			panic(err)
		}
		eval, err := jsonpath.EvalPathsInBytes(responseBody, paths)
		if err != nil {
			panic(err)
		}

		// TODO optimization: Don't reinitialize each time, reuse this somehow.
		resultsArray := make([]string, 0, 10)
		for {
			if result, ok := eval.Next(); ok {

				value := strings.TrimSpace(result.Pretty(false))
				resultsArray = append(resultsArray, trimChar(value, '"'))
			} else {
				break
			}
		}
		if eval.Error != nil {
			return
			//panic(eval.Error)
		}

		passResultIntoSessionMap(resultsArray, httpAction, sessionMap)
	}

	// if httpAction.ResponseHandler.Xmlpath != "" {
	// 	path := xmlpath.MustCompile(httpAction.ResponseHandler.Xmlpath)
	// 	r := bytes.NewReader(responseBody)
	// 	root, err := xmlpath.Parse(r)
	//
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}
	//
	// 	iterator := path.Iter(root)
	// 	hasNext := iterator.Next()
	// 	if hasNext {
	// 		resultsArray := make([]string, 0, 10)
	// 		for {
	// 			if hasNext {
	// 				node := iterator.Node()
	// 				resultsArray = append(resultsArray, node.String())
	// 				hasNext = iterator.Next()
	// 			} else {
	// 				break
	// 			}
	// 		}
	// 		passResultIntoSessionMap(resultsArray, httpAction, sessionMap)
	// 	}
	// }

	// log.Println(string(responseBody))
}

/**
 * Trims leading and trailing byte r from string s
 */
func trimChar(s string, r byte) string {
	sz := len(s)

	if sz > 0 && s[sz-1] == r {
		s = s[:sz-1]
	}
	sz = len(s)
	if sz > 0 && s[0] == r {
		s = s[1:sz]
	}
	return s
}

func passResultIntoSessionMap(resultsArray []string, httpAction HttpAction, sessionMap map[string]string) {
	resultCount := len(resultsArray)

	if resultCount > 0 {
		switch httpAction.ResponseHandler.Index {
		case FIRST:
			sessionMap[httpAction.ResponseHandler.Variable] = resultsArray[0]
			break
		case LAST:
			sessionMap[httpAction.ResponseHandler.Variable] = resultsArray[resultCount-1]
			break
		case RANDOM:
			if resultCount > 1 {
				sessionMap[httpAction.ResponseHandler.Variable] = resultsArray[rand.Intn(resultCount-1)]
			} else {
				sessionMap[httpAction.ResponseHandler.Variable] = resultsArray[0]
			}
			break
		}

	} else {
		// TODO how to handle requested, but missing result?
	}
}

//HmacSha256Encode - 產生 merchantkey
func HmacSha256Encode(timestamp string, secretkey string) string {
	mac := hmac.New(sha256.New, []byte(secretkey))
	mac.Write([]byte(timestamp))
	expectedMAC := mac.Sum(nil)
	hmacStr := hex.EncodeToString(expectedMAC)

	return hmacStr
}

func wtfHash(data string) string {
	var m map[string]interface{}
	hash := wtfhash.JSONtoMD5([]byte(data), "testKey")

	err := json.Unmarshal([]byte(data), &m)
	if err != nil {
		return data
	}
	m["hash"] = hash
	result, err := json.Marshal(m)
	if err != nil {
		return data
	}
	return string(result)
}

func writeLog(body []byte, title string) {
	var m map[string]interface{}
	err := json.Unmarshal(body, &m)
	if err != nil {
		writeFile(fmt.Sprintln(string(body), ">", title))
		return
	}

	if v, ok := m["error"]; ok {
		if v == "0" || v == 0.0 {
			//writeFile(fmt.Sprintln(string(body), ">", title))
			return
		}
	}
	if v, ok := m["code"]; ok {
		if v == "0" || v == 0.0 {
			//writeFile(fmt.Sprintln(string(body), ">", title))
			return
		}
	}
	writeFile(fmt.Sprintln(string(body), ">", title))
}

// 檔案是否存在，是：開啟，否：建立
func logFile() (f *os.File, err error) {
	fileDate := time.Now().Format("2006-01-02")

	//fileName := fmt.Sprint(exepath.Get()+"/"+fileDate, ".log") // build
	fileName := fmt.Sprint(fileDate, ".log") // run

	// 文件是否已存在
	if _, err := os.Stat(fileName); os.IsNotExist(err) {
		// 建立文件
		f, err = os.Create(fileName)
		fmt.Println("\x1b[32;1m" + "create file: " + fileName + "\x1b[0m")
	} else {
		// 開啟文件
		f, err = os.OpenFile(fileName, os.O_APPEND|os.O_RDWR, 0666)
	}
	return
}

// 寫入檔案
func writeFile(str string) {
	// 建立or開啟檔案
	f, err := logFile()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(str)

	_, err = io.WriteString(f, str+"\n")
	if err != nil {
		fmt.Println(err)
		return
	}
	f.Close()
}

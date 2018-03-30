/*********** Package vaptchasdk for golang (第三方) **********/
package vaptchasdk

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	//版本
	VERSION = "1.0.0"
	//SDK语言
	SDK_LANG = "golang"
	//V URL
	API_URL = "http://api.vaptcha.com"
	//获取流水号 Url
	GetChallenge_URL = "/challenge"
	//验证 Url
	VALIDATE_URL = "/validate"
	//验证数量使用完
	REQUEST_UESD_UP = "0209"

	//宕机模式检验恢复时间=ms
	DOWNTIME_CHECK_TIME = 185000
	//宕机模式二次验证失效时间=ms
	VALIDATE_PASS_TIME = 600000
	//宕机模式请求失效的时间=ms
	REQUEST_ABATE_TIME = 250000
	//宕机模式验证等待时间=ms
	VALIDATE_WAIT_TIME = 2000

	//宕机模式保存通过数量最大值=50000
	MAX_LENGTH = 50000
	//验证图的后缀
	PIC_POST_FIX = ".png"
	//宕机模式key路径
	PUBLIC_KEY_PATH = "http://down.vaptcha.com/publickey"
	//是否宕机路径
	IS_DOWN_PATH = "http://static.vaptcha.com/isdown"
	//宕机模式图片路径
	DOWN_TIME_PATH = "downtime/"
)

type vaptcha struct {
	id                string
	key               string
	isDown            bool
	publicKey         string
	lastCheckDownTime int64
	passedSignatures  string
}

//Vaptcha 操作接口
type Vaptcha interface {
	GetChallenge(sceneID string) interface{}
	Validate(challenge, token, sceneID string) bool
	Downtime(data string) string
	NormalValidate(challenge, token, sceneID string) bool
	DowntimeValidate(token string) bool
	GetSignature(_time int64) string
	DownTimeCheck(time1 int64, time2 int64, signature, captcha string) string
	HmacSHA1(key, query string) string
	GetRequest(url string) string
	PostRequest(url, text string) string
	IsDown() bool
	GetDowntimeVaptcha() string
	GetPublicKey() string
	GetUnixTime() int64
	MD5Encrypt(text string) string
}

//New   返回操作接口
//vid : 注册创建获取
//key : 注册创建获取
func New(vid, key string) Vaptcha {
	return &vaptcha{
		id:                vid,
		key:               key,
		isDown:            false,
		publicKey:         "",
		lastCheckDownTime: 0,
		passedSignatures:  "",
	}
}

func (v *vaptcha) GetChallenge(sceneID string) interface{} {
	url := API_URL + GetChallenge_URL
	now := v.GetUnixTime()
	query := "id=" + v.id + "&scene=" + sceneID + "&time=" + strconv.FormatInt(now, 10)
	signature := v.HmacSHA1(v.key, query)
	if !v.isDown {
		_url := url + "?" + query + "&signature=" + signature
		challenge := v.GetRequest(_url)
		predicateOne := challenge == REQUEST_UESD_UP
		predicateTwo := !(challenge != "") && v.IsDown()
		if predicateOne || predicateTwo {
			v.lastCheckDownTime = now
			v.isDown = true
			v.lastCheckDownTime = 0
			return v.GetDowntimeVaptcha()
		}
		return fmt.Sprintf("{\"vid\":\"%s\",\"challenge\":\"%s\"}", v.id, challenge)
	}
	if now-v.lastCheckDownTime > DOWNTIME_CHECK_TIME {
		v.lastCheckDownTime = now
		challenge := v.GetRequest(url)
		if challenge != "" && challenge != REQUEST_UESD_UP {
			v.isDown = false
			v.passedSignatures = ""
			return fmt.Sprintf("{\"vid\":\"%s\",challenge\":\"%s\"}", v.id, challenge)
		}
		return v.GetDowntimeVaptcha()
	}

	return nil
}
func (v *vaptcha) Validate(challenge, token, sceneID string) bool {
	if !v.isDown && challenge != "" {
		return v.NormalValidate(challenge, token, sceneID)
	}
	return v.DowntimeValidate(token)

}
func (v *vaptcha) Downtime(data string) string {
	if !(data != "") {
		return "{\"error\":\"parms error\"}"
	}
	datas := strings.Split(data, ",")
	if datas[0] == "request" {
		return v.GetDowntimeVaptcha()
	} else if datas[0] == "getsignature" {
		if len(datas) < 2 {
			return "{\"error\":\"parms error\"}"
		}
		if _time, err := strconv.ParseInt(datas[1], 10, 64); err == nil {
			return v.GetSignature(_time)
		}
		return "{\"error\":\"parms error\"}"

	} else if datas[0] == "check" {
		if len(datas) < 5 {
			return "{\"error\":\"parms error\"}"
		}
		time1, err := strconv.ParseInt(datas[1], 10, 64)
		if err != nil {
			return "{\"error\":\"parms error\"}"
		}
		time2, err := strconv.ParseInt(datas[2], 10, 64)
		if err != nil {
			return "{\"error\":\"parms error\"}"
		}
		signature := datas[3]
		captcha := datas[4]
		return v.DownTimeCheck(time1, time2, signature, captcha)
	}
	return "{\"error\":\"parms error\"}"
}
func (v *vaptcha) NormalValidate(challenge, token, sceneID string) bool {
	if !(challenge != "") || !(token != "") || token != v.MD5Encrypt(v.key+"vaptcha"+challenge) {
		return false
	}
	url := API_URL + VALIDATE_URL
	query := fmt.Sprintf("id=%s&scene=%s&token=%s&time=%s", v.id, sceneID, token, strconv.FormatInt(v.GetUnixTime(), 10))
	signature := v.HmacSHA1(v.key, query)
	response := v.PostRequest(url, query+"&signature="+signature)
	return response == "success"
}
func (v *vaptcha) DowntimeValidate(token string) bool {
	if !(token != "") {
		return false
	}
	strs := strings.Split(token, ",")
	if len(strs) < 2 {
		return false
	}
	_time, _ := strconv.ParseInt(strs[0], 10, 64)
	signature := strs[1]
	now := v.GetUnixTime()
	if now-_time > VALIDATE_PASS_TIME {
		return false
	}
	signatureTrue := v.MD5Encrypt(string(_time) + v.key + "vaptcha")
	if signature == signatureTrue {
		if strings.Count(v.passedSignatures, signature) != 0 {
			return false
		}
		v.passedSignatures += signature
		length := len(v.passedSignatures)
		if length > MAX_LENGTH {
			v.passedSignatures = strings.Replace(v.passedSignatures, v.passedSignatures[0:length-MAX_LENGTH+1], "", 1)
			log.Printf("passedSignatures :%s", v.passedSignatures)

		}
		return true
	}
	return false
}
func (v *vaptcha) GetSignature(_time int64) string {
	now := v.GetUnixTime()
	if now-_time > REQUEST_ABATE_TIME {
		return ""
	}
	signature := v.MD5Encrypt(strconv.FormatInt(now, 10) + v.key)
	return fmt.Sprintf("{\"time\":\"%s\",signature\":\"%s\"}", strconv.FormatInt(now, 10), signature)

}
func (v *vaptcha) DownTimeCheck(time1 int64, time2 int64, signature, captcha string) string {
	now := v.GetUnixTime()
	if now-time1 > REQUEST_ABATE_TIME || signature != v.MD5Encrypt(string(time2)+v.key) ||
		now-time2 < VALIDATE_WAIT_TIME {
		return "{\"result\":false}"
	}
	trueCaptcha := v.MD5Encrypt(string(time1) + v.key)[0:3]
	if trueCaptcha == strings.ToLower(captcha) {
		return fmt.Sprintf("{\"result\":true,\"token\":\"%s\",%s}", strconv.FormatInt(now, 10), v.MD5Encrypt(strconv.FormatInt(now, 10)+v.key+"vaptcha"))
	}
	return "{\"result\":false}"

}
func (v *vaptcha) HmacSHA1(key, text string) string {
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write([]byte(text))
	encryptsBytes := mac.Sum(nil)
	signature := base64.StdEncoding.EncodeToString(encryptsBytes)
	signature = strings.Replace(
		strings.Replace(
			strings.Replace(signature, "=", "", -1), "+", "", -1), "/", "", -1)
	return signature
}
func (v *vaptcha) GetRequest(url string) string {
	resp, err := http.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(body)
}
func (v *vaptcha) PostRequest(url, text string) string {
	buf := bytes.NewBuffer([]byte(text))
	resp, err := http.Post(url, "application/x-www-form-urlencoded", buf)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(body)
}

func (v *vaptcha) IsDown() bool {
	result := v.GetRequest(IS_DOWN_PATH)
	return result != ""
}
func (v *vaptcha) GetDowntimeVaptcha() string {
	now := v.GetUnixTime()
	md5 := v.MD5Encrypt(strconv.FormatInt(now, 10) + v.key)
	captcha := md5[0:3]
	verificationKey := md5[30:]
	if !(v.publicKey != "") {
		v.publicKey = v.GetPublicKey()
	}
	url := v.MD5Encrypt(
		captcha+verificationKey+v.GetPublicKey()) + PIC_POST_FIX
	url = DOWN_TIME_PATH + url
	return fmt.Sprintf("{"+"\"time:\":\"%s\",\"url\":\"%s\"}", strconv.FormatInt(now, 10), url)
}
func (v *vaptcha) GetPublicKey() string {
	return v.GetRequest(PUBLIC_KEY_PATH)
}

func (v *vaptcha) GetUnixTime() int64 {
	//将纳秒转换为毫秒
	return time.Now().UnixNano() / 1e6
}
func (v *vaptcha) MD5Encrypt(text string) string {
	h := md5.New()
	h.Write([]byte(text))
	data := h.Sum(nil)
	return fmt.Sprintf("%x", data)
}

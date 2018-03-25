package vaptchasdk

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io/ioutil"
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
	GET_CHALLENGE_URL = "/challenge"
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
	_id               int
	key               string
	isDown            bool
	publicKey         string
	lastCheckDownTime int64
	passedSignatures  string
}

type Vaptcha interface {
	Get_challenge(scene_id string) interface{}
	Validate(challenge, token, scene_id string) bool
	Downtime(data string)
	Normal_validate(challenge, token, scene_id string) bool
	Downtime_validate(token string) bool
	Get_signature(_time int64) string
	Down_time_check(time1 int64, time2 int64, signature, captcha string) string
	Hmac_sha1(key, query string) string
	Get_request(url string) string
	Post_request(url, text string) string
	Get_isdown() bool
	Get_downtim_captcha() string
	Get_public_key() string
	To_unix_time() int64
	Md5_encode(text string) string
}

func New(id int, key string) Vaptcha {
	return &vaptcha{
		_id:               id,
		key:               key,
		isDown:            false,
		publicKey:         "",
		lastCheckDownTime: 0,
		passedSignatures:  "",
	}
}

func (v *vaptcha) Get_challenge(scene_id string) interface{} {
	url := API_URL + GET_CHALLENGE_URL
	now := v.To_unix_time()
	query := "id=" + fmt.Sprintln(v._id) + "&scence=" + scene_id + "&time" + string(v.To_unix_time())
	signature := v.Hmac_sha1(v.key, query)
	if !v.isDown {
		_url := url + "?" + query + "&signature=" + signature
		challenge := v.Get_request(_url)
		predicate_one := challenge == REQUEST_UESD_UP
		predicate_two := (!(challenge != "") && v.Get_isdown())
		if predicate_one || predicate_two {
			v.lastCheckDownTime = now
			v.isDown = true
			v.lastCheckDownTime = 0
			return v.Get_downtim_captcha()
		}
		return fmt.Sprintf("{"+"\"vid\":\"%s\",\"challenge\":\"%s\"}", string(v._id), string(challenge))
	} else if now-v.lastCheckDownTime > DOWNTIME_CHECK_TIME {
		v.lastCheckDownTime = now
		challenge := v.Get_request(url)
		if challenge != "" && challenge != REQUEST_UESD_UP {
			v.isDown = false
			v.passedSignatures = ""
			return fmt.Sprintf("{\"vid\":\"%s\",challenge\":\"%s\"}", string(v._id), string(challenge))
		}
		return v.Get_downtim_captcha()
	}
	return nil
}
func (v *vaptcha) Validate(challenge, token, scene_id string) bool {
	if !v.isDown && challenge != "" {
		return v.Normal_validate(challenge, token, scene_id)
	}
	return v.Downtime_validate(token)

}
func (v *vaptcha) Downtime(data string) {

}
func (v *vaptcha) Normal_validate(challenge, token, scene_id string) bool {
	if !(challenge != "") || !(token != "") || token != v.Md5_encode(v.key+"vaptcha"+challenge) {
		return false
	}
	url := API_URL + VALIDATE_URL
	query := fmt.Sprintf("id=%s&scene=%s&token=%s&time=%s", v._id, scene_id, token, string(v.To_unix_time()))
	signature := v.Hmac_sha1(v.key, query)
	response := v.Post_request(url, query+"&signature="+signature)
	return response == "success"
}
func (v *vaptcha) Downtime_validate(token string) bool {
	if !(token != "") {
		return false
	}
	strs := strings.Split(token, ",")
	if len(strs) < 2 {
		return false
	}
	_time, _ := strconv.Atoi(strs[0])
	signature := strs[1]
	now := v.To_unix_time()
	if now-int64(_time) > VALIDATE_PASS_TIME {
		return false
	}
	signatureTrue := v.Md5_encode(string(_time) + v.key + "vaptcha")
	if signature == signatureTrue {
		if strings.Count(v.passedSignatures, signature) != 0 {
			return false
		}
		v.passedSignatures += signature
		length := len(v.passedSignatures)
		if length > MAX_LENGTH {
			v.passedSignatures = strings.Replace(v.passedSignatures, v.passedSignatures[0:length-MAX_LENGTH+1], "", 1)
			return true
		}

	}
	return false

}
func (v *vaptcha) Get_signature(_time int64) string {
	now := v.To_unix_time()
	if now-_time > REQUEST_ABATE_TIME {
		return ""
	}
	signature := v.Md5_encode(string(now) + v.key)
	return fmt.Sprintf("{\"time\":\"%s\",signature\":\"%s\"}", string(now), signature)

}
func (v *vaptcha) Down_time_check(time1 int64, time2 int64, signature, captcha string) string {
	now := v.To_unix_time()
	if now-time1 > REQUEST_ABATE_TIME || signature != v.Md5_encode(string(time2)+v.key) ||
		now-time2 < VALIDATE_WAIT_TIME {
		return "{\"result\":false}"
	}
	trueCaptcha := v.Md5_encode(string(time1) + v.key)[0:3]
	if trueCaptcha == strings.ToLower(string(captcha)) {
		return fmt.Sprintf("{\"result\":true,\"token\":\"%s\",%s}", string(now), v.Md5_encode(string(now)+v.key+"vaptcha"))
	}
	return "{\"result\":false}"

}
func (v *vaptcha) Hmac_sha1(key, query string) string {
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write([]byte(query))
	encryptsBytes := mac.Sum(nil)
	signature := base64.StdEncoding.EncodeToString(encryptsBytes)
	signature = strings.Replace(signature, "=", "", -1)
	signature = strings.Replace(signature, "/", "", -1)
	result := strings.Replace(signature, "+", "", -1)
	return result
}
func (v *vaptcha) Get_request(url string) string {
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
func (v *vaptcha) Post_request(url, text string) string {
	buf := bytes.NewBuffer([]byte(text))
	resp, err := http.Post(url, "application/json", buf)
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

func (v *vaptcha) Get_isdown() bool {
	result := v.Get_request(IS_DOWN_PATH)
	if result == "" {
		return false
	}
	return true
}
func (v *vaptcha) Get_downtim_captcha() string {
	now := v.To_unix_time()
	md5 := v.Md5_encode(string(now) + v.key)
	captcha := md5[0:3]
	verificationKey := md5[30:]
	if !(v.publicKey != "") {
		v.publicKey = v.Get_public_key()
	}
	url := v.Md5_encode(captcha+verificationKey+v.Get_public_key()) + PIC_POST_FIX
	url = DOWN_TIME_PATH + url
	return fmt.Sprintf("{"+"\"time:\":\"%s\",\"url\":\"%s\"}", string(now), string(url))
}
func (v *vaptcha) Get_public_key() string {
	return v.Get_request(PUBLIC_KEY_PATH)
}

func (v *vaptcha) To_unix_time() int64 {
	//将纳秒转换为毫秒
	return (time.Now().UnixNano() / 1e6)
}
func (v *vaptcha) Md5_encode(text string) string {
	data := md5.Sum([]byte(text))
	return string(data[:])
}

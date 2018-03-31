package main

import (
	"errors"
	"log"
	"net/http"
	"os"
	"vaptcha-golang-sdk/example/conf"
	"vaptcha-golang-sdk/example/util"
	"vaptcha-golang-sdk/vaptchasdk"
)

//vid,key 请自行到vaptcha官网注册获取
//vid,key 放在/conf/conf.yaml的配置文件中

//获取文件的目录
var projectDir = util.GetProjectDir()

//获取配置.yaml文件的操作接口
var confOperator = conf.New(projectDir + string(os.PathSeparator) + "conf" + string(os.PathSeparator) + "conf.yaml")

//获取vaptcha操作接口
var vaptcha = vaptchasdk.New(confOperator.Get("vid").(string), confOperator.Get("key").(string))

func main() {
	http.HandleFunc("/getvaptcha", HTTPGetvaptcha)
	http.HandleFunc("/downtime", HTTPDownTime)
	http.HandleFunc("/validate", HTTPValidate)
	err := http.ListenAndServe(":9090", nil)
	if err != nil {
		panic(err)
	}
}

/*
	以下函数用于模拟client与server的交互,实际生产环境请根据业务要求
*/

func HTTPGetvaptcha(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		data := []byte(Getvaptcha())
		_, err := w.Write(data)
		if err != nil {
			log.Fatalf("return getvaptcha err: %s", err.Error())
		}
	}
}

func HTTPDownTime(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	r.ParseForm()
	data := r.PostFormValue("data")
	if data != "nil" {
		result := Downtime(data)
		_, err := w.Write([]byte(result))
		if err != nil {
			log.Fatalf("return getvaptcha err: %s", err.Error())
		}
	}
	_, err := w.Write([]byte("argument illegal"))
	if err != nil {
		log.Fatalf("return getvaptcha err: %s", err.Error())
	}
}

func HTTPValidate(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	buf := make([]byte, 10)
	for {
		_, err := r.Body.Read(buf)
		if err != nil {
			break
		}
	}
	//之后对读取到的buf进行操作(根据上传的数据的格式)
}

/*

	以下是对vaptcha的操作函数

*/

//Getvaptcha 获取流水号接口，用于获取vid和challenge
//return {"vid":"xxxxxxxxxxxx","challenge":xxxxxxxxxxxxxx}
func Getvaptcha() string {
	vidAndChallenge := vaptcha.GetChallenge("")
	if vidAndChallenge != nil {
		if value, ok := (vidAndChallenge).(string); ok {
			return value
		}
		return ""
	}
	return ""
}

//Downtime 宕机模式接口，用户宕机模式的相关验证，仅用于和Vaptcha客户端sdk交互
//​data type：字符串
//return type：json
func Downtime(data string) string {
	downtime := vaptcha.Downtime(data)
	if downtime != "" {
		return data
	}
	return data
}

//Validate 二次验证接口，用于与Vaptcha服务器的二次验证。
//chanllange type：string
//token type：string
//scene_id type：string (nil)
func Validate(chanllenge, token, sceneID string) error {
	if chanllenge == "" || token == "" {
		return errors.New("argument error")
	}
	if ok := vaptcha.Validate(chanllenge, token, sceneID); ok {
		return nil
	}
	return errors.New("Validate fail")
}

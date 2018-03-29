package conf

import (
	"io/ioutil"
	"log"

	yaml "gopkg.in/yaml.v2"
)

//************* 加载配置文件包括vid，key 等 ************//

type conf struct {
	//存放conf所有配置信息
	confMaps map[string]interface{}
}

//Conf 配置文件接口
type Conf interface {
	Get(key string) interface{}
}

func New(confFilePath string) Conf {
	confFile, err := ioutil.ReadFile(confFilePath)
	if err != nil {
		log.Fatalf("confFile.Get err   #%v ", err)
	}
	c := &conf{
		confMaps: make(map[string]interface{}),
	}
	log.Printf("conf's content is : %s", string(confFile))
	err = yaml.Unmarshal(confFile, c.confMaps)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}
	return c
}

//Get 根据key获取对应的value
func (c *conf) Get(key string) interface{} {
	if key != "" {
		if value, ok := c.confMaps[key]; ok {
			return value
		}
	}
	return nil
}

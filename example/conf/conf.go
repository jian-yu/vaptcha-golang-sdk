package conf

import (
	"io/ioutil"
	"log"
	"sync"

	yaml "gopkg.in/yaml.v2"
)

//************* 加载配置文件包括vid，key ************//

type conf struct {
	//存放conf所有配置信息
	confMaps map[string]interface{}
	//配置文件相对于项目目录的路径
	filepath string
}

//Conf 配置文件接口
type Conf interface {
	Get(key string) interface{}
	GetFilePath() string
}

var instantiated *conf
var once sync.Once

//New 放回一个配置文件的操作接口
//filepath 文件相对于项目目录的路径
func New(filepath string) Conf {
	//instantiated 只初始化一次
	once.Do(func() {
		confFile, err := ioutil.ReadFile(filepath)
		if err != nil {
			log.Fatalf("confFile.Get err   #%v ", err)
		}
		instantiated = &conf{
			confMaps: make(map[string]interface{}),
			filepath: filepath,
		}
		log.Printf("conf's content is : %s", string(confFile))
		err = yaml.Unmarshal(confFile, instantiated.confMaps)
		if err != nil {
			log.Fatalf("Unmarshal: %v", err)
		}
	})
	return instantiated
}

func (c *conf) Get(key string) interface{} {
	if key != "" {
		if value, ok := c.confMaps[key]; ok {
			return value
		}
	}
	return nil
}

func (c *conf) GetFilePath() string {
	return c.filepath
}

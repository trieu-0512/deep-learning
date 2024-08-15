#include "StdAfx.h"
#include "VarKey.h"
#include "Dut.h"
#include "Config.h"
#include "CommonApi.h"
#include "Iphlpapi.h"
#include "SFIS_Api.h"
#include "SFISLibApi.h"
#include <direct.h>
#include <regex>
#include <codecvt>
#include "io.h"
#include "UsbTree.h"
#include "FileStatusList.h"
#include "GoTogether.h"
#include "Gcheckpoint.h"
#include "Gassembly.h"
#include "Gcomponents.h"
#include "Shlwapi.h"
#include ".\modules\others\ToolVer.h"
#include "modules\datapool\DataPool.h"
#include "modules\robotarm\RobotCmdData.h"
#include "modules\robotarm\RobotActionDefine.h"
#include "modules\comportdbg\ComPortDbg.h"
#include <iomanip>
#include <sstream>
#include <string>
#include <iostream>

#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "Shlwapi.lib")

extern HWND	g_uiwnd;
extern string g_data1, g_data2, g_data3;

static CCriticalSection g_sfis_cs;
static CCriticalSection g_sfis_cs2;
static CCriticalSection g_adb_dev_cs;
static CCriticalSection g_adb_cmd_cs;
static CCriticalSection g_only_one_cs;
static CCriticalSection g_file_status_list_cs;
static CCriticalSection g_popup_input_cs;
static CCriticalSection g_comport_cs;

extern CCriticalSection g_producer_cs;
extern CCriticalSection g_datapool_cs;



enum RouteStat
{
	ROUTE_WRONG_STEP = 10,
	ROUTE_OVER_COUNT,
	ROUTE_REAPIR_FAIL,
	ROUTE_RULE_FAIL,
	ROUTE_UNKNOW,
	ROUTE_OK = 0
};

CDut::CDut(UI_ATTR* ui_attr) :m_id_no(ui_attr->no), m_id_name(ui_attr->name), m_test_mode(ui_attr->testMode), m_repeat_count(ui_attr->repeatCount), m_scenario_name(ui_attr->scenarioFile), m_check_route_pass(false), m_route_status(ROUTE_UNKNOW), m_upload_test_result_pass(false), m_dut_id(""), m_dut_comport(""), m_tag(ui_attr->name), m_error_code(""), m_is_rel(false), m_isn(ui_attr->name), m_myftp(NULL)
{
	m_tag = "[" + m_tag + "]";
	output_debug("[fox] CDut()++");

	Together::g_together_cs.Enter();
	CGoTogether::getInstance()->Add(m_id_name.c_str());
	Together::g_together_cs.Leave();

	create_temp();

	m_ui = new CUIReponse(g_uiwnd, m_id_no, m_id_name.c_str());
	m_sfiscsv = new CSfisCsv(ui_attr->name, m_temp_path.c_str());
	m_rdlog = new CRdLog(ui_attr->name, ".txt", m_temp_path.c_str());
	m_gpiblog = new CRdLog(ui_attr->name, ".gpib", m_temp_path.c_str());
	CConfig::getInstance()->GetUnitConfig(m_id_name.c_str(), m_config);
	memcpy_s(m_input_data, sizeof(m_input_data), ui_attr->inputData, sizeof(m_input_data));

	m_command["INIT"] = &CDut::cmd_init;
	m_command["WAIT"] = &CDut::cmd_wait;
	m_command["MESSAGE"] = &CDut::cmd_message;
	m_command["TOGETHER"] = &CDut::cmd_together;
	m_command["ONLY_ONE"] = &CDut::cmd_only_one;
	m_command["RUN_ONCE"] = &CDut::cmd_run_once;
	m_command["JUST_TEST"] = &CDut::just_test;
	m_command["END_TEST"] = &CDut::cmd_end_test;
	m_command["SFIS_CHECK_ROUTE"] = &CDut::cmd_sfis_check_route;
	m_command["SFIS_STATION_INPUT_CHECK"] = &CDut::cmd_sfis_check_route;
	m_command["SFIS_GET_PREVIOUS_RESULT"] = &CDut::cmd_sfis_get_previous_result;
	m_command["SFIS_GET_CONFIG"] = &CDut::cmd_sfis_get_config;
	m_command["STATION_MAC"] = &CDut::cmd_mac_addr;
	m_command["TEST_GET_ISN_FROM_UI"] = &CDut::cmd_get_isn_from_ui;
	m_command["ADB_DEVICES"] = &CDut::cmd_adb_devices;
	m_command["FASTBOOT_DEVICES"] = &CDut::cmd_fastboot_devices;
	m_command["GET_ISN_FATP"] = &CDut::cmd_get_isn_fatp;
	m_command["GET_SYSENV_INFO"] = &CDut::cmd_get_sysenv_info;
	m_command["GET_SYSENV_INFO_MLB"] = &CDut::cmd_get_sysenv_info_mlb;
	m_command["TEST_ADB_COMMAND"] = &CDut::cmd_adb_command;

	m_command["TEST_MULTI_ADB_COMMAND"] = &CDut::multi_adb_command;	//min add 20210125
	m_command["BUTTON_CMD_ADB_PICTRUE"] = &CDut::check_button_cmd_adb_pic_have_timeout;	//min add 20210204
	//////////////////////////////
	m_command["ADD_PICTRUE_ITEMS"] = &CDut::check_ADD_PICTRUE_ITEMS;	// add by Hai 20220716
	//////////////////////////////
	m_command["TEST_FASTBOOT_COMMAND"] = &CDut::cmd_fastboot_command;
	m_command["TEST_FASTBOOT_COMMAND2"] = &CDut::cmd_fastboot_command2;
	m_command["TEST_ADB_WAIT_FOR_DEVICE"] = &CDut::cmd_adb_wait_for_device;
	m_command["TEST_FASTBOOT_WAIT_FOR_DEVICE"] = &CDut::cmd_fastboot_wait_for_device;
	m_command["TEST_CONSOLE_CMD"] = &CDut::cmd_console_cmd;
	m_command["TEST_SELF_COMPORT"] = &CDut::cmd_self_comport;
	m_command["TEST_OPEN_COMPORT"] = &CDut::cmd_open_serial;
	m_command["TEST_SERIAL_COMMAND"] = &CDut::cmd_serial_command;
	m_command["TEST_CLOSE_COMPORT"] = &CDut::cmd_close_serial;

	m_command["TEST_FASTBOOT_FLASH"] = &CDut::cmd_fastboot_flash;
	m_command["TEST_FASTBOOT_FLASH2"] = &CDut::cmd_fastboot_flash2;
	m_command["TEST_FASTBOOT_FLASH_UNLOCK"] = &CDut::cmd_fastboot_flash_unlock;
	m_command["GET_SYSENV_ITEM"] = &CDut::cmd_get_sysenv_item;
	m_command["SET_SYSENV_ITEM"] = &CDut::cmd_set_sysenv_item;
	m_command["SFIS_UPLOAD_SAVE_ITEM"] = &CDut::cmd_upload_save_item;
	m_command["SFIS_INPUT_DATA_FROM_UI"] = &CDut::cmd_input_data_ui;
	m_command["TEST_TELNET_OPEN"] = &CDut::cmd_telnet_open;
	m_command["TEST_TELNET_COMMAND"] = &CDut::cmd_telnet_command;
	m_command["TEST_READ_QRCODE"] = &CDut::cmd_read_qrcode;
	m_command["TEST_CHECK_QR_CODE"] = &CDut::cmd_check_qrcode;
	m_command["TEST_COMPARE_WITH_SFIS"] = &CDut::cmd_compare_with_sfis;
	m_command["TEST_COMPARE_WIFI_MAC"] = &CDut::cmd_compare_wifi_mac;
	m_command["TEST_COMPARE_15_4_MAC"] = &CDut::cmd_compare_15_4_mac;
	m_command["TEST_CHECK_SFIS_INFO"] = &CDut::cmd_check_sfis_info;
	m_command["TEST_SWDL_EXCLUDE_90PN"] = &CDut::cmd_swdl_exclude_90pn;
	m_command["TEST_SWDL_SEC_EXCLUDE_90PN"] = &CDut::cmd_swdl_sec_exclude_90pn;
	m_command["TEST_READY_FOR_FLASH"] = &CDut::cmd_ready_for_flash;
	m_command["GET_INFO_FILE_PLIST"] = &CDut::cmd_get_info_file_plist;
	m_command["TEST_CHECK_INFO"] = &CDut::cmd_check_info;
	m_command["TEST_CHECK_INFO2"] = &CDut::cmd_check_info2;
	m_command["TEST_CHECK_INFO3"] = &CDut::cmd_check_info3;
	m_command["TEST_90PN_MAP_IMAGE"] = &CDut::cmd_90pn_map_image;
	m_command["TEST_CHECK_REBOOT"] = &CDut::cmd_check_reboot;
	m_command["TEST_GET_ISN_FROM_QRCODE"] = &CDut::cmd_get_isn_from_qrcode;
	m_command["TEST_ALS"] = &CDut::cmd_als_test;

	//DMM & PPS
	m_command["PPS_ON"] = &CDut::pps_on;
	m_command["PPS_OFF"] = &CDut::pps_off;
	m_command["PPS_SET_VOL"] = &CDut::pps_set_vol;
	m_command["PPS_SET_CURR"] = &CDut::pps_set_curr;
	m_command["PPS_MEAS_CURR"] = &CDut::pps_meas_curr;
	m_command["ROUTE_OPEN"] = &CDut::route_open;
	m_command["ROUTE_CLOSE"] = &CDut::route_close;
	m_command["MEAS_VOL"] = &CDut::meas_vol;
	m_command["MEAS_CURR"] = &CDut::meas_curr;

	m_command["CheckPoint_Log"] = &CDut::cmd_checkpoint_Log;
	m_command["Assembly_Log"] = &CDut::cmd_assembly_Log;
	m_command["Components_Log"] = &CDut::cmd_components_log;

	// add by Vic
	m_command["MESSAGE_PIC_DEMO"] = &CDut::cmd_message_pic_demo;
	//m_command["MESSAGE_PIC"] = &CDut::popup_pic_msg_form;
	// add by Vic -- end --

	//add by Isaac
	//W/R ISN 
	m_command["WRITE_ISN"] = &CDut::cmd_write_isn;
	m_command["READ_ISN"] = &CDut::cmd_read_isn;

	//Gucci RUNIN Station
	//m_command["PARSE_LOG"] = &CDut::cmd_read_runin_log_file;
	//m_command["IMAGE_CHECK"] = &CDut::cmd_image_check;
	m_command["TEST_ADB_COMMAND_MB"] = &CDut::cmd_adb_command_mb;
	m_command["TEST_ADB_COMMAND_EX"] = &CDut::cmd_adb_command_ex;
	// add by Isaac -- end --

	// add by Brighd -- start	20180130
	m_command["WHEN"] = &CDut::cmd_when;
	// add by Brighd -- end		20180202
	m_command["DUT_CONNECT_TIME"] = &CDut::cmd_dut_connect_time; //jack add
	m_command["TEST_REBOOT_DUT"] = &CDut::cmd_test_reboot_dut; //jack add
	m_command["CMD_CONTROL_LIGHT_PANEL"] = &CDut::cmd_control_light_panel; //jack add
	output_debug("CDut()--");
}

CDut::~CDut(void)
{
	output_debug("~CDut()++");

	Together::g_together_cs.Enter();
	CGoTogether::getInstance()->Remove(m_id_name.c_str());
	Together::g_together_cs.Leave();

	delete m_ui;
	delete m_sfiscsv;
	delete m_rdlog;
	delete m_gpiblog;
	delete m_myftp;

	for (map<string, CRS232*>::iterator it = m_com.begin(); it != m_com.end(); it++)
	{
		delete it->second;
		it->second = NULL;
	}
	for (map<string, CMyTelnet*>::iterator it = m_telnet.begin(); it != m_telnet.end(); it++)
	{
		delete it->second;
		it->second = NULL;
	}


	output_debug("~CDut()--");
}

void CDut::output_debug(const char* fmt, ...)
{
	char buffer[4096];
	va_list	list;

	strcpy_s(buffer, m_tag.c_str());
	va_start(list, fmt);
	vsprintf_s(buffer + strlen(buffer), _countof(buffer) - strlen(buffer), fmt, list);
	va_end(list);
	::OutputDebugStringA(buffer);
}

int CDut::just_test(const char* item, const Json::Value& param)
{
	string readstr = "";
	//char r[128];

	//if (use_comport("JIG") != NULL)
	{
		/*int n = use_comport("JIG1")->Open();
		m_rdlog->WriteLogf(" open:%d\n", n);
		n = use_comport("JIG1")->WRString("TG\r", readstr, 200);
		m_rdlog->WriteLogf("WR:%d read:%s\n", n, readstr.c_str());
		output_debug("serial#:%s", readstr.c_str());

		use_comport("JIG1")->Close();*/
	}


	//if (use_gpibdev("INS1") != NULL)
	{
		//use_gpibdev("INS1")->ROUTE_OPEN(201);
		//use_gpibdev("INS1")->GPIB_QUERY("*IDN?", r);
	}
	log_sfis_and_set_info_no_judge("TEST_A", CSfisCsv::Pass, "X0000000000011");

	::Sleep((DWORD)MyRandom(1.0, 7.0) * 1000);

	vector<string> getver;
	/*sfis_get_version("17AA01AC151700N1", "MO_D", "DEVICE", "", getver);
	strcpy_s(CSFIS_Api::getInstance()->m_sfis_st.szDeviceID, getver[2].c_str());
	sfis_get_version("17AA01AC151700N1", "TSP_RESULT", "", "", getver);*/
	//m_rdlog->WriteLogf("===>%s\n", getver[2].c_str());

	//sfis_get_previous_result("17AA01AC3317004X", getver);
	//log_sfis_and_set_info_no_judge(item, CSfisCsv::Pass, r);


	return 1;
}

int CDut::StartTest()
{
	string item_name;
	Json::Value item_param;
	Json::Value test_items;

	CMyTimer timer(this->m_ui);

	timer.Start();

	read_scenario_file(m_scenario_name.c_str(), test_items);

	m_ui->SetRangeProgress(test_items.size() + 1);

	if (before_test() != ERROR_SUCCESS)
	{
		return 0;
	}

	m_rdlog->WriteLogfEX(SystemLevel, "### START_TEST ###\n\n");

	for (unsigned int i = 0; i < test_items.size(); i++)
	{
		item_name = test_items[i].getMemberNames()[0];
		item_param = test_items[i][item_name];

		m_ui->UpdateProgress();
		//m_ui->SetTextProgress(item_name.c_str());

		if (item_name == "END_TEST")
			break;

		if (m_exit_test == true)
			break;

		if (m_exit_test_and_no_sfis == true)
			break;

		int ret = run_script_command(item_name, item_param);
		if (ret == ERROR_NOT_FOUND)
			break;
	}

	m_other_dut.PreEndTest(item_param);

	m_rdlog->WriteLogfEX(SystemLevel, "### END_TEST ###\n");
	cmd_end_test(item_name.c_str(), test_items[test_items.size() - 1][item_name]);

	m_other_dut.PostEndTest(item_param);
	after_test();

	m_ui->SetMaxProgress();
	m_ui->EnableButton(true);
	return 0;
}

int CDut::run_script_command(string& item_name, Json::Value& item_param)
{
	int ret = RET_FAIL;
	string replaced_item_name = item_name;
	CCalcPeriod period;
	SYSTEMTIME tim;

	replace_test_item_name(item_param, replaced_item_name);

	period.GetTimeA(&tim);
	m_rdlog->WriteLogfEX(SystemLevel, "[%s]++\n", item_name.c_str());

	test_item_special_attribute_set(item_param);

	if (m_command.find(item_name) != m_command.end())
	{
		ret = (this->*m_command[item_name])(replaced_item_name.c_str(), item_param);
	}
	else
	{
		CSubDut* sub_dut = m_other_dut.HaveTestItem(item_name.c_str());

		if (sub_dut != NULL)
		{
			ret = sub_dut->RunScriptCommand(item_name, replaced_item_name, item_param);
		}
		else
		{
			::MessageBoxA(g_uiwnd, string(item_name + " is not define!").c_str(), 0, 0);
			m_rdlog->WriteLogf(" %s is not define!\n EXIT TEST!!\n", item_name.c_str());
			m_exit_test_and_no_sfis = true;
			ret = ERROR_NOT_FOUND;
		}
	}

	if ((CConfig::getInstance()->cfg_debug_when_fail) && (ret != S_OK))
	{
		SuspendTest();
	}

	test_item_special_attribute_restore();

	period.GetTimeB(&tim);
	m_rdlog->WriteLogfEX(SystemLevel, "[%s]--\n %s,total_test_time: %4.3f sec\n\n", item_name.c_str(), replaced_item_name.c_str(), (float)period.GetDiff() / 1000);

	return ret;
}

void CDut::replace_test_item_name(const Json::Value& item_param, string& item_nmae)
{
	if (item_param.isObject())
		if (item_param.isMember("item_name"))
			item_nmae = item_param["item_name"].asString();
}

void CDut::test_item_special_attribute_set(Json::Value& item_param)
{
	m_var[WRITE_TO_CSV] = ParamBool(item_param, WRITE_TO_CSV, true);
	m_var[LIMIT_BY_SKU] = ParamBool(item_param, LIMIT_BY_SKU, false);
}

void CDut::test_item_special_attribute_restore()
{
	m_var[WRITE_TO_CSV] = true;
	m_var[LIMIT_BY_SKU] = false;
}

int CDut::run_sub_script_command(const Json::Value& test_items)
{
	int ret = RET_SUCCESS;
	Json::Value sub_script_test_items;
	string item_name;
	Json::Value item_param;

	if (!test_items.isNull())
	{
		if (test_items.isMember("sub_script"))
		{
			sub_script_test_items = test_items["sub_script"];
			for (unsigned int i = 0; i < sub_script_test_items.size(); i++)
			{
				item_name = sub_script_test_items[i].getMemberNames()[0];
				item_param = sub_script_test_items[i][item_name];

				if (item_name[0] == '#')
					continue;

				ret += run_script_command(item_name, item_param);
			}
		}
	}

	return ret;
}

int CDut::before_test()
{
	m_exit_test = false;
	m_exit_test_and_no_sfis = false;

	reset_ui();
	m_ui->UpdateStatus("Running");

	return ERROR_SUCCESS;
}

int CDut::after_test()
{
	CRobotCmdData rbt_cmd_data;
	int final_ret = m_var["final_ret"].asInt();
	if (final_ret == 0)
	{
		if (m_error_code.empty() == true)
		{
			rbt_cmd_data.m_robot_scenario = RobotAction::RBT_DUT_PASS;
		}
		else
		{
			rbt_cmd_data.m_robot_scenario = RobotAction::RBT_DUT_AB_FAIL;
			rbt_cmd_data.m_err_code = m_error_code;
		}
	}
	else
	{
		rbt_cmd_data.m_robot_scenario = RobotAction::RBT_EXCEPTION;
		rbt_cmd_data.m_err_code = "IFAY7Z";
	}

	rbt_cmd_data.m_dut_name = m_id_name;
	rbt_cmd_data.m_isn = m_isn;
	rbt_cmd_data.DataPoolIn();

	remove_temp(m_temp_path);

	return 0;
}

void CDut::read_scenario_file(const char* file_name, Json::Value& test_items)
{
	byte			bom_header[] = { 0xef, 0xbb, 0xbf, 0x00 };
	string			data;
	Json::Reader	reader;
	Json::Value		root;

	ReadFileBin(file_name, data);

	if (data.compare(0, strlen((const char*)&bom_header[0]), (const char*)&bom_header[0]) == 0)
		data.erase(0, strlen((const char*)&bom_header[0]));

	if (reader.parse(data, root, false))
	{
		m_scenario_ver = root["Version"].asString();
		test_items = root["Script"];
	}
	else
		::MessageBoxA(g_uiwnd, "failed to read scenario file!", "Warning", MB_OK);


	Json::Value::Members members;
	Json::Value valid_items;

	for (unsigned int i = 0; i < test_items.size(); i++)
	{
		members = test_items[i].getMemberNames();

		if (members[0][0] != '#')
			valid_items.append(test_items[i]);

		if (members[0] == "END_TEST")
			break;
	}

	test_items.clear();
	test_items = valid_items;
}

void CDut::reset_ui()
{
	m_ui->UpdateProgress(0);
	m_ui->UpdateIsn("");
	m_ui->UpdateStatus("Ready");
	m_ui->UpdateTimer("0");
	m_ui->EnableButton(false);
	m_ui->ClearInfo();
}

void CDut::create_temp()
{
	string path;

	GetCurrentPath(m_temp_path);
	m_temp_path += "\\" + m_id_name;

	path = m_temp_path + "\\*.*";
	//RemoveAllFiles(path.c_str());

	backup_temp();

	remove_temp(m_temp_path);

	_mkdir(m_temp_path.c_str());
}

void CDut::backup_temp()
{
	string dst_path;
	char timestamp[64];
	Json::Value ext_name;

	if (PathFileExistsA(m_id_name.c_str()))
	{
		ext_name = CConfig::getInstance()->cfg_crash_backup;
		GetSystemDateTimeFormatB(timestamp, _countof(timestamp));
		dst_path = "crash_backup\\" + m_id_name + "_" + timestamp;

		gen_zip(dst_path.c_str(), ext_name);
	}
}

void CDut::remove_temp(string& dir)
{
	DeleteDirectory(dir);
}

void CDut::gen_zip(const char* zip_name, Json::Value& ext_name)
{
	CDOS dos;
	char cmd[512];
	string src_path;
	string result;

	for (unsigned int i = 0; i < ext_name.size(); i++)
	{
		src_path = m_id_name + "\\" + ext_name[i].asString();
		sprintf_s(cmd, "7z.exe a %s %s", zip_name, src_path.c_str());
		dos.Send(cmd, result, 10000);
	}
}

void CDut::create_backup_path()
{
	string mode_path = "\\";

	/*if (m_test_mode == OnLine)
		mode_path += PATH_ONLINE;
	else if (m_test_mode == OffLine)
		mode_path += PATH_OFFLINE;
	else
		mode_path += PATH_OFFLINE + string("\\") + PATH_QTR;*/

	if (m_route_status != ROUTE_UNKNOW)
		mode_path += PATH_ONLINE;
	else if (m_repeat_count != 0)
		mode_path += PATH_SPC;
	else if (m_test_mode != TestMode::QTR)
		mode_path += PATH_OFFLINE;
	else
		mode_path += PATH_OFFLINE + string("\\") + PATH_QTR;

	m_local_path = "";
	m_server_path = "";
	m_local_path = m_local_path + CConfig::getInstance()->cfg_log_dir + "\\" + CConfig::getInstance()->cfg_project_name + "\\" + CConfig::getInstance()->cfg_run_stage + "\\" + CConfig::getInstance()->cfg_station_id + "\\" + CConfig::getInstance()->cfg_device_id + mode_path;
	m_server_path = m_server_path + CConfig::getInstance()->cfg_server_log.directory + "\\" + CConfig::getInstance()->cfg_project_name + "\\" + CConfig::getInstance()->cfg_run_stage + "\\" + CConfig::getInstance()->cfg_station_id + "\\" + CConfig::getInstance()->cfg_device_id + mode_path;
}

int CDut::sfis_check_rule(int count)
{
	int ret = RET_FAIL;
	char temp[256];
	char devid[32] = { 0 };
	vector<string> getver;

	if (CConfig::getInstance()->cfg_sfis_route_rule == "N/A")
		return RET_SUCCESS;

	ret = sfis_get_version(m_isn.c_str(), "MO_D", "DEVICE", "", getver);

	if ((ret == RET_SUCCESS) && (getver.size() > 2))
		strcpy_s(devid, getver[2].c_str());
	if (ret == RET_SUCCESS)
	{
		if (CConfig::getInstance()->cfg_sfis_route_rule == "AAB")
		{
			if (CSfisCsv::Pass, CConfig::getInstance()->cfg_device_id == devid)
			{
				if (count % 2 == 1)
					ret = ROUTE_RULE_FAIL;
			}
			else
			{
				if (count % 2 == 0)
					ret = ROUTE_RULE_FAIL;
			}

			if (ret == ROUTE_RULE_FAIL)
			{
				sprintf_s(temp, " The route rule is AAB. And the last failure on device id %s.", devid);
				::MessageBoxA(g_uiwnd, temp, "Warning", MB_OK);
			}
		}
		else if (CConfig::getInstance()->cfg_sfis_route_rule == "ABA")
		{
			if (CSfisCsv::Pass, CConfig::getInstance()->cfg_device_id == devid)
			{
				if (count % 2 == 0)
					ret = ROUTE_RULE_FAIL;
			}
			else
			{
				if (count % 2 == 1)
					ret = ROUTE_RULE_FAIL;
			}

			if (ret == ROUTE_RULE_FAIL)
			{
				sprintf_s(temp, " The route rule is ABA. And the last failure on device id %s.", devid);
				::MessageBoxA(g_uiwnd, temp, "Warning", MB_OK);
			}
		}
		else
		{
			m_rdlog->WriteLog(" SFIS_CHECK_RULE is either [AAB] or [ABA].\n");
			::MessageBoxA(g_uiwnd, "SFIS_CHECK_RULE is either [AAB] or [ABA]. Disable the rule if [N/A].", "Warning", MB_OK);
			ret = ROUTE_RULE_FAIL;
		}
	}

	return ret;
}

int CDut::sfis_check_route(string& msg)
{
	INT		iStatus = ERROR_SUCCESS;
	CHAR	szTmpBuffer[1024] = { 0x00 };
	string	result;

	if (m_is_rel == true)
		return iStatus;

	m_check_route_pass = false;
	m_route_status = ROUTE_UNKNOW;

	if (0 != m_isn.length())
	{
		strcpy_s(CSFIS_Api::getInstance()->m_sfis_st.szISN, m_isn.c_str());
	}
	else
	{
		msg = "ISN is empty. Can not check route.\n";
		m_rdlog->WriteLog(msg.c_str());
		//::MessageBox(NULL, "ISN is empty. Can not check route.", NULL, NULL);
		return -1;
	}
	LPSFIS_INTERFACE lp;
	lp = &CSFIS_Api::getInstance()->m_sfis_st;
	if (!CConfig::getInstance()->cfg_new_sfis_dll)
		iStatus = CSFIS_Api::getInstance()->m_pfnSFIS_CheckRoute(CSFIS_Api::getInstance()->m_sfis_st);
	else
	{
		iStatus = CSFISLibApi::getInstance()->ChkRoute(m_isn.c_str(), result);
		if (!result.empty())
			strcpy_s(CSFIS_Api::getInstance()->m_sfis_st.szMessage, result.c_str());
		else
		{
			CSFISLibApi::getInstance()->GetErrMsg(result);
			strcpy_s(CSFIS_Api::getInstance()->m_sfis_st.szMessage, result.c_str());
		}
	}

	output_debug("m_pfnSFIS_CheckRoute(1)\n");
	m_rdlog->WriteLog(" m_pfnSFIS_CheckRoute(1)\n");
	msg = "m_pfnSFIS_CheckRoute(1)\n";
	if (0 != strlen(CSFIS_Api::getInstance()->m_sfis_st.szMessage))
	{
		//strncpy_s(szTmpBuffer, m_stSFIS.szMessage, sizeof(szTmpBuffer));
		output_debug(CSFIS_Api::getInstance()->m_sfis_st.szMessage);
		m_rdlog->WriteLogf(CSFIS_Api::getInstance()->m_sfis_st.szMessage);
		msg = msg + CSFIS_Api::getInstance()->m_sfis_st.szMessage + "\n";
	}

	if (ERROR_SUCCESS != iStatus)
	{
		output_debug("m_pfnSFIS_CheckRoute fail");
		m_rdlog->WriteLog("\n m_pfnSFIS_CheckRoute fail\n");
		msg = msg + "m_pfnSFIS_CheckRoute fail\n";

		if ((CConfig::getInstance()->cfg_enable_repair == true) && strstr(CSFIS_Api::getInstance()->m_sfis_st.szMessage, "REPAIR OF"))
		{
			// Get Test Count Algorithm
			CHAR* pcBuffer;
			INT iCount = 0;
			pcBuffer = strstr(CSFIS_Api::getInstance()->m_sfis_st.szMessage, "[LF#:") + 5;
			if (pcBuffer)
			{
				for (int i = 0; i < 4; i++)
				{
					if (pcBuffer[i] == ']')
					{
						iCount = atoi(pcBuffer);
						break;
					}
				}
			}
			//iCount = 1;  ///Hai add 22/07/30
			// Check Target Repair Count
			if ((0 < iCount) && (iCount >= CConfig::getInstance()->cfg_sfis_repair_count))
			{
				sprintf_s(szTmpBuffer, "OVER REPAIR COUNT = %d", iCount);
				//msg = "OVER REPAIR COUNT = " + iCount;
				output_debug(szTmpBuffer);
				m_rdlog->WriteLogf(" %s\n", szTmpBuffer);
				msg = msg + szTmpBuffer + "\n";
				//::MessageBoxA(NULL, CSFIS_Api::getInstance()->m_sfis_st.szMessage, NULL, NULL);
				m_route_status = ROUTE_OVER_COUNT;
				return ROUTE_OVER_COUNT;
			}

			iStatus = sfis_check_rule(iCount);
			if (ERROR_SUCCESS != iStatus)
			{
				m_route_status = iStatus;
				return iStatus;
			}

			// Auto Repair
			iStatus = sfis_auto_repair();
			if (ERROR_SUCCESS != iStatus)
			{
				output_debug("Failed to auto repair.\n%s", CSFIS_Api::getInstance()->m_sfis_st.szMessage);
				m_rdlog->WriteLogf(" Failed to auto repair.\n%s", CSFIS_Api::getInstance()->m_sfis_st.szMessage);
				msg = msg + "Failed to auto repair.\n" + CSFIS_Api::getInstance()->m_sfis_st.szMessage + "\n";
				m_route_status = ROUTE_REAPIR_FAIL;
				return ROUTE_REAPIR_FAIL;
			}
			else
			{
				m_rdlog->WriteLog(CSFIS_Api::getInstance()->m_sfis_st.szMessage);
			}
			// Check Route again
			if (!CConfig::getInstance()->cfg_new_sfis_dll)
				iStatus = CSFIS_Api::getInstance()->m_pfnSFIS_CheckRoute(CSFIS_Api::getInstance()->m_sfis_st);
			else
			{
				iStatus = CSFISLibApi::getInstance()->ChkRoute(m_isn.c_str(), result);
				if (!result.empty())
					strcpy_s(CSFIS_Api::getInstance()->m_sfis_st.szMessage, result.c_str());
				else
				{
					CSFISLibApi::getInstance()->GetErrMsg(result);
					strcpy_s(CSFIS_Api::getInstance()->m_sfis_st.szMessage, result.c_str());
				}
			}
			//strncpy_s(m_TestValue[iDutNo], m_stSFIS.szMessage, sizeof(m_stSFIS.szMessage));
			output_debug("m_pfnSFIS_CheckRoute(2)\n%s", CSFIS_Api::getInstance()->m_sfis_st.szMessage);
			m_rdlog->WriteLogf(" m_pfnSFIS_CheckRoute(2)\n%s", CSFIS_Api::getInstance()->m_sfis_st.szMessage);
			if (ERROR_SUCCESS != iStatus)
			{
				/*m_rdlog->WriteLogf(" m_pfnSFIS_CheckRoute(2)\n%s", CSFIS_Api::getInstance()->m_sfis_st.szMessage);*/
				msg = msg + "\nm_pfnSFIS_CheckRoute(2)\n" + CSFIS_Api::getInstance()->m_sfis_st.szMessage + "\n";
				//::MessageBoxA(NULL, CSFIS_Api::getInstance()->m_sfis_st.szMessage, NULL, NULL);
				m_route_status = ROUTE_WRONG_STEP;
				return ROUTE_WRONG_STEP;
			}
		}
		else
		{
			m_rdlog->WriteLogf(" %s\n", CSFIS_Api::getInstance()->m_sfis_st.szMessage);
			msg = msg + CSFIS_Api::getInstance()->m_sfis_st.szMessage + "\n";
			//::MessageBoxA(NULL, CSFIS_Api::getInstance()->m_sfis_st.szMessage, NULL, NULL);
			m_route_status = ROUTE_WRONG_STEP;
			return ROUTE_WRONG_STEP;
		}
	}

	m_check_route_pass = true;
	m_route_status = ROUTE_OK;
	return iStatus;
}

int CDut::sfis_auto_repair()
{
	INT iStatus = RET_FAIL;
	string result = "";
	//iStatus = CSFIS_Api::getInstance()->CheckConnection(); ///Hai add 22/07/30
	if (!CConfig::getInstance()->cfg_new_sfis_dll)
		iStatus = CSFIS_Api::getInstance()->m_pfnSFIS_Repair(CSFIS_Api::getInstance()->m_sfis_st);
	else
	{
		iStatus = CSFISLibApi::getInstance()->Repair(m_isn.c_str(), result);
	}

	if (ERROR_SUCCESS != iStatus)
	{
		if (!CConfig::getInstance()->cfg_new_sfis_dll)
			::MessageBoxA(NULL, CSFIS_Api::getInstance()->m_sfis_st.szMessage, NULL, NULL);
		else
		{
			if (!result.empty())
				::MessageBoxA(NULL, result.c_str(), NULL, NULL);
		}
		return SFIS_REPAIR_FAIL;
	}

	return iStatus;
}

int CDut::sfis_get_version(const char* isn, const char* type, const char* data1, const char* data2, vector<string>& getver)
{
	INT iStatus = RET_FAIL;
	char delim[] = { 0x7f, 0x00 };

	g_sfis_cs.Enter();

	if (!CConfig::getInstance()->cfg_new_sfis_dll)
	{
		strcpy_s(CSFIS_Api::getInstance()->m_sfis_st.szISN, isn);
		strcpy_s(CSFIS_Api::getInstance()->m_sfis_st.szGetVersionType, type);
		strcpy_s(CSFIS_Api::getInstance()->m_sfis_st.szCheckData, data1);
		strcpy_s(CSFIS_Api::getInstance()->m_sfis_st.szCheckData2, data2);

		iStatus = CSFIS_Api::getInstance()->m_pfnSFIS_GetVersion(CSFIS_Api::getInstance()->m_sfis_st);

		if (CSFIS_Api::getInstance()->m_sfis_st.szMessage[0] == '0')
		{
			m_rdlog->WriteLogf(" ISN:%s\n GetVerType:%s\n ChkData:%s\n ChkData2:%s\n", isn, type, data1, data2);
		}

		if ((iStatus != ERROR_SUCCESS) && (strcmp(CSFIS_Api::getInstance()->m_sfis_st.szMessage, "SFIS Error Code (0x9010)") == 0))
		{
			iStatus = CSFIS_Api::getInstance()->CheckConnection();
			iStatus = CSFIS_Api::getInstance()->Login(CSFIS_Api::getInstance()->m_sfis_st.szUserID);
			m_rdlog->WriteLogf(" m_pfnSFIS_Login = %s\n", CSFIS_Api::getInstance()->m_sfis_st.szMessage);

			strcpy_s(CSFIS_Api::getInstance()->m_sfis_st.szGetVersionType, type);
			iStatus = CSFIS_Api::getInstance()->m_pfnSFIS_GetVersion(CSFIS_Api::getInstance()->m_sfis_st);
		}

		m_rdlog->WriteLogf(" m_pfnSFIS_GetVersion = %s\n", CSFIS_Api::getInstance()->m_sfis_st.szMessage);

		if (iStatus == ERROR_SUCCESS)
		{
			StringToken(CSFIS_Api::getInstance()->m_sfis_st.szMessage, getver, delim);
			if (CSFIS_Api::getInstance()->m_sfis_st.szMessage[0] == '0')
				iStatus = RET_FAIL;
		}
	}
	else
	{
		string result = "";
		iStatus = CSFISLibApi::getInstance()->GetVersion(isn, type, data1, data2, result);

		if (iStatus == ERROR_SUCCESS)
			StringToken(result.c_str(), getver, delim);

		if (!result.empty())
			m_rdlog->WriteLogf(" SFIS GetVersion() = %s\n", result.c_str());
	}

	g_sfis_cs.Leave();

	return iStatus;
}

int CDut::sfis_get_version(const char* isn, const char* deviceid, const char* type, const char* data1, const char* data2, vector<string>& getver)
{
	int iStatus = RET_FAIL;
	char delim[] = { 0x7f, 0x00 };
	string result = "";

	g_sfis_cs.Enter();

	iStatus = CSFISLibApi::getInstance()->GetVersion(isn, deviceid, type, data1, data2, result);

	if (iStatus == ERROR_SUCCESS)
		StringToken(result.c_str(), getver, delim);

	if (!result.empty())
		m_rdlog->WriteLogf(" SFIS GetVersion() = %s\n", result.c_str());
	g_sfis_cs.Leave();

	return iStatus;
}

int CDut::sfis_get_previous_result(const char* isn, vector<string>& getver)
{
	INT iStatus = RET_FAIL;
	char backup_devid[32];

	g_sfis_cs2.Enter();

	iStatus = sfis_get_version(isn, "MO_D", "DEVICE", "", getver);

	if ((iStatus == ERROR_SUCCESS) && (getver.size() > 2))
	{
		strcpy_s(backup_devid, CSFIS_Api::getInstance()->m_sfis_st.szDeviceID);
		strcpy_s(CSFIS_Api::getInstance()->m_sfis_st.szDeviceID, getver[2].c_str());

		if (!CConfig::getInstance()->cfg_new_sfis_dll)
			iStatus = sfis_get_version(isn, "TSP_RESULT", "", "", getver);
		else
			iStatus = sfis_get_version(isn, getver[2].c_str(), "TSP_RESULT", "", "", getver);

		strcpy_s(CSFIS_Api::getInstance()->m_sfis_st.szDeviceID, backup_devid);
	}
	g_sfis_cs2.Leave();

	return iStatus;
}

int CDut::sfis_test_result()
{
	int iStatus = ERROR_SUCCESS;
	int failed_count = m_sfiscsv->GetFailCount();
	int result_n_times = CConfig::getInstance()->cfg_sfis_write_result_n_times_when_fail;

	if (m_is_rel == true)
		return iStatus;

	strcpy_s(CSFIS_Api::getInstance()->m_sfis_st.szISN, m_isn.c_str());
	strcpy_s(CSFIS_Api::getInstance()->m_sfis_st.szLogFile, m_sfiscsv->GetCsvFullName());

	if (result_n_times < 1) result_n_times = 1;
	//result_n_times = 2; ///Hai add 22/07/29
	if (!CConfig::getInstance()->cfg_new_sfis_dll)
	{

		for (int n = 0; n < result_n_times; n++)
		{
			iStatus = CSFIS_Api::getInstance()->m_pfnSFIS_TestResult(CSFIS_Api::getInstance()->m_sfis_st);

			if (strstr(CSFIS_Api::getInstance()->m_sfis_st.szMessage, "Login First!") != NULL)
			{
				m_rdlog->WriteLogf(" m_pfnSFIS_TestResult = %s\n", CSFIS_Api::getInstance()->m_sfis_st.szMessage);

				iStatus = CSFIS_Api::getInstance()->Login(CSFIS_Api::getInstance()->m_sfis_st.szUserID);
				m_rdlog->WriteLogf(" Login again!\n Login = %s\n", CSFIS_Api::getInstance()->m_sfis_st.szMessage);

				iStatus = CSFIS_Api::getInstance()->m_pfnSFIS_TestResult(CSFIS_Api::getInstance()->m_sfis_st);
			}

			if (failed_count == 0) break;

			if ((n < (result_n_times - 1)) && (failed_count != 0))
			{
				sfis_auto_repair();
				m_rdlog->WriteLogf(" TestResult then Repair (%d)\n", n);
			}
		}

		if (strstr(CSFIS_Api::getInstance()->m_sfis_st.szMessage, "TEST DATA:SAVED! STATUS:[1]") == NULL)
			iStatus = RET_FAIL;

		output_debug("m_pfnSFIS_TestResult = %s", CSFIS_Api::getInstance()->m_sfis_st.szMessage);
		m_rdlog->WriteLogf(" m_pfnSFIS_TestResult(SFIS msg) = %s\n", CSFIS_Api::getInstance()->m_sfis_st.szMessage);
		::OutputDebugStringA(CSFIS_Api::getInstance()->m_sfis_st.szLogStreamData);
		m_rdlog->WriteLogf(" m_pfnSFIS_TestResult(SFIS dat) = %s\n", CSFIS_Api::getInstance()->m_sfis_st.szLogStreamData);
	}
	else
	{
		string result;
		string stream_data;
		stream_data = CSFISLibApi::getInstance()->GetStreamData();
		for (int n = 0; n < result_n_times; n++)
		{
			result = "";
			iStatus = CSFISLibApi::getInstance()->Result(m_isn.c_str(), this->m_error_code.c_str(), stream_data.c_str(), result);

			if (result.find("Login First!") != string::npos)
			{
				m_rdlog->WriteLogf(" SFIS Login = %s\n", result.c_str());

				CSFISLibApi::getInstance()->Login(result);
				m_rdlog->WriteLogf(" Login again!\n Login = %s\n", result.c_str());

				iStatus = CSFISLibApi::getInstance()->Result(m_isn.c_str(), this->m_error_code.c_str(), stream_data.c_str(), result);
			}

			if (failed_count == 0) break;

			if ((n < (result_n_times - 1)) && (failed_count != 0))
			{
				sfis_auto_repair();
				m_rdlog->WriteLogf(" TestResult then Repair (%d)\n", n);
			}
		}

		if (result.find("TEST DATA:SAVED! STATUS:[1]") == string::npos)
			iStatus = RET_FAIL;

		output_debug("SFIS Result = %s", result.c_str());
		m_rdlog->WriteLogf(" SFIS result = %s\n", result.c_str());
		::OutputDebugStringA(CSFIS_Api::getInstance()->m_sfis_st.szLogStreamData);
		m_rdlog->WriteLogf(" SFIS stream data = %s\n", stream_data.c_str());
	}

	m_upload_test_result_pass = (iStatus == ERROR_SUCCESS) ? true : false;

	return iStatus;
}

int CDut::ParamInt(const Json::Value& param, const char* key, int v_default)
{
	return (param.type() == Json::objectValue && param.isMember(key)) ? param[key].asInt() : v_default;
}

double CDut::ParamDouble(const Json::Value& param, const char* key, double v_default)
{
	return (param.type() == Json::objectValue && param.isMember(key)) ? param[key].asDouble() : v_default;
}

bool CDut::ParamBool(const Json::Value& param, const char* key, bool v_default)
{
	return (param.type() == Json::objectValue && param.isMember(key)) ? param[key].asBool() : v_default;
}

void CDut::ParamStr(const Json::Value& param, const char* key, string& out_str, const char* v_default)
{
	out_str = (param.type() == Json::objectValue && param.isMember(key)) ? param[key].asString() : v_default;
}

void CDut::set_info(const char* item, CSfisCsv::Status stat, const char* value)
{
	m_ui->SetInfo(item, stat, value, "N/A", "N/A");
}

void CDut::set_info(const char* item, CSfisCsv::Status stat, double value)
{
	char v[128];

	sprintf_s(v, "%.4f", value);

	m_ui->SetInfo(item, stat, v, "N/A", "N/A");
}

int CDut::log_sfis_save_item_and_set_info(const char* item, const char* value, bool write_really)
{
	m_sfiscsv->WriteCsvSaveItem(item, value, write_really);
	m_ui->SetInfo(item, CSfisCsv::Pass, value, "N/A", "N/A");

	return 0;
}

int CDut::log_sfis_and_set_info(const char* item, const char* value, bool no_log_if_fail)
{
	char temp[256];
	int judge_stat;
	string item_name = item;
	CSfisCsv::Status csv_stat = CSfisCsv::Fail;
	CCriteria::CriteriaField criteria;
	string uplimit = "N/A";
	string downlimit = "N/A";

	if (m_var[WRITE_TO_CSV].asBool() == true)
	{
		if (m_var[LIMIT_BY_SKU].asBool() == true)
			item_name = item_name + "_" + m_var[SFIS_SKU].asString();

		judge_stat = CCriteria::getInstance()->GetCriteriaResult(item_name.c_str(), value, &criteria);

		if (judge_stat != CCriteria::NotFound)
		{
			csv_stat = (judge_stat == CCriteria::Pass) ? CSfisCsv::Pass : CSfisCsv::Fail;
			uplimit = criteria.ul;
			downlimit = criteria.dl;
		}
		else
		{
			sprintf_s(temp, " Can not find item \"%s\" in the critria file!\n Call PE please.\n", item_name.c_str());
			m_rdlog->WriteLog(temp);
			if (CConfig::getInstance()->cfg_warning_when_item_not_in_criteria)
			{
				::MessageBoxA(g_uiwnd, temp, "Warning", MB_OK);
				m_exit_test_and_no_sfis = true;
			}
		}

		if (csv_stat == CSfisCsv::Pass || (no_log_if_fail == true && csv_stat == CSfisCsv::Fail))
		{
			m_sfiscsv->WriteCsv(item_name.c_str(), csv_stat, value, uplimit.c_str(), downlimit.c_str());
			m_ui->SetInfo(item_name.c_str(), csv_stat, value, uplimit.c_str(), downlimit.c_str());
			m_producer.AddCsv(item_name.c_str(), csv_stat, value, uplimit.c_str(), downlimit.c_str(), "");
		}
	}

	return csv_stat;
}

int CDut::log_sfis_and_set_info(const char* item, double value)
{
	char v[128];

	sprintf_s(v, "%.4f", value);

	return log_sfis_and_set_info(item, v);
}

int CDut::log_sfis_and_set_info_no_judge(const char* item, CSfisCsv::Status stat, const char* value, bool no_log_if_fail)
{
	if (m_var[WRITE_TO_CSV].asBool() == true)
	{
		if (stat == CSfisCsv::Pass || (no_log_if_fail == true && stat == CSfisCsv::Fail))
		{
			m_sfiscsv->WriteCsv(item, stat, value, "N/A", "N/A");
			m_producer.AddCsv(item, stat, value, "", "", "");
		}
	}

	if (stat == CSfisCsv::Pass || (no_log_if_fail == true && stat == CSfisCsv::Fail))
		m_ui->SetInfo(item, stat, value, "N/A", "N/A");

	return stat;
}

int CDut::log_sfis_and_set_info_no_judge(const char* item, CSfisCsv::Status stat, int value)
{
	char v[128];

	sprintf_s(v, "%d", value);

	return log_sfis_and_set_info_no_judge(item, stat, v);
}

int CDut::log_sfis_and_set_info_no_judge(const char* item, CSfisCsv::Status stat, double value)
{
	char v[128];

	sprintf_s(v, "%.4f", value);

	return log_sfis_and_set_info_no_judge(item, stat, v);
}

BOOL CDut::move_all_files_to(const char* dst_path, bool unless)
{
	char temp[128];
	string chk_filename;
	string chk_assembly_filename;
	string chk_components_filename;
	BOOL copy_ok = TRUE;
	SYSTEMTIME st;
	::GetLocalTime(&st);

	char date[64];
	sprintf_s(date, "%.4d%.2d%.2d", st.wYear, st.wMonth, st.wDay);

	string dst_dir;
	dst_dir = string(dst_path) + "\\PASS\\" + date;
	CreateFolder(dst_dir.c_str());
	dst_dir = string(dst_path) + "\\FAIL\\" + date;
	CreateFolder(dst_dir.c_str());

	dst_dir = string(dst_path) + ((m_error_code.empty() == true) ? "\\PASS\\" : "\\FAIL\\") + date;

	string new_log_name, new_csv_name;

	if (unless == false)
	{
		new_log_name = dst_dir + "\\" + m_rdlog->m_file_name + ".txt";
		copy_ok &= ::CopyFileA(m_rdlog->m_full_name.c_str(), new_log_name.c_str(), true);

		if (copy_ok == FALSE)
		{
			sprintf_s(temp, "[fox] failed to copy .txt. last error:%d", ::GetLastError());
			//::MessageBoxA(g_uiwnd, temp, "MultiTest", MB_OK);
			::OutputDebugStringA(temp);
			::CopyFileA(m_rdlog->m_full_name.c_str(), new_log_name.c_str(), true);
		}

		if (PathFileExistsA(m_gpiblog->m_full_name.c_str()))
		{
			new_log_name = dst_dir + "\\" + m_gpiblog->m_file_name + m_gpiblog->m_ext_name;
			copy_ok &= ::CopyFileA(m_gpiblog->m_full_name.c_str(), new_log_name.c_str(), true);

			if (copy_ok == FALSE)
			{
				sprintf_s(temp, "[fox] failed to copy .gpib. last error:%d", ::GetLastError());
				::OutputDebugStringA(temp);
				::CopyFileA(m_gpiblog->m_full_name.c_str(), new_log_name.c_str(), true);
			}
		}
	}

	new_csv_name = dst_dir + "\\" + m_sfiscsv->m_file_name + ".csv";
	BOOL copy_ok2 = ::CopyFileA(m_sfiscsv->m_full_name.c_str(), new_csv_name.c_str(), true);
	if (copy_ok2 == FALSE)
	{
		sprintf_s(temp, "[fox] failed to copy .csv. last error:%d", ::GetLastError());
		//::MessageBoxA(g_uiwnd, temp, "MultiTest", MB_OK);
		::OutputDebugStringA(temp);
		::CopyFileA(m_sfiscsv->m_full_name.c_str(), new_csv_name.c_str(), true);
	}
	copy_ok &= copy_ok2;

	//CheckPoint_Log
	if (m_var.isMember("CheckPoint_Log"))
	{
		chk_filename = CConfig::getInstance()->cfg_project_name + string("_PSZ_") + date + "_checkpoint";
		add_check_point(chk_filename.c_str(), dst_dir.c_str());
	}

	//Assembly_Log
	if (m_var.isMember("Assembly_Log"))
	{
		chk_assembly_filename = CConfig::getInstance()->cfg_project_name + string("_PSZ_") + date + "_assembly";
		add_assembly(chk_assembly_filename.c_str(), dst_dir.c_str());
	}
	//Components_Log
	if (m_var.isMember("Components_Log"))
	{
		chk_components_filename = CConfig::getInstance()->cfg_project_name + string("_PSZ_") + date + "_components";
		add_components(chk_components_filename.c_str(), dst_dir.c_str());
	}
	return copy_ok;
}

void CDut::record_file_status_list(const char* file_name, int flag)
{
	char temp[512];
	CFileStatusList fsl(m_local_path.c_str(), CConfig::getInstance()->cfg_station_id.c_str(), CConfig::getInstance()->cfg_device_id.c_str());

	if (flag == 1)
	{
		CDOS dos;
		char dos_cmd[100] = { 0 };
		char ip[128];
		char* p;
		char* q;
		string dos_return;
		strcpy_s(ip, CConfig::getInstance()->cfg_server_log.directory.c_str());
		p = strstr(ip, "\\\\");
		p += 2;
		q = strstr(p, "\\");
		*q = 0;

		sprintf_s(dos_cmd, "ping %s -n 1", p);
		dos.Send(dos_cmd, dos_return, 10000);

		if (strstr(dos_return.c_str(), "ms"))
		{
			flag = 2;
		}
	}

	g_file_status_list_cs.Enter();

	sprintf_s(temp, "%s.csv,%d", file_name, flag);
	fsl.AddContent(temp);
	fsl.CopyTo(m_server_path.c_str());

	g_file_status_list_cs.Leave();
}

void CDut::add_check_point(const char* name, const char* dir)
{
	CCheckPointInfo info;

	info.manufacturer = "PSZ";
	info.location = "Suzhou";
	info.gpn = "g01";
	info.mpn = "n01";
	info.serial_number = m_isn;
	info.station_name = CConfig::getInstance()->cfg_station_id.c_str();
	info.station_id = CConfig::getInstance()->cfg_device_id.c_str();
	info.station_type = "TEST";
	info.line = "FATP";
	info.line_id = CConfig::getInstance()->cfg_line_num.c_str();
	info.op_id = CSFIS_Api::getInstance()->m_sfis_st.szUserID;
	info.build_phase = CConfig::getInstance()->cfg_run_stage;
	info.status = (m_error_code.empty() ? "PASS" : "FAIL");
	info.failure_code = m_error_code;
	info.remarks = (m_error_code.empty() ? "PASS" : "FAIL");

	CheckPoint::g_checkpoint_cs.Enter();
	CGcheckpoint::getInstance()->SetPathName(name, dir);
	CGcheckpoint::getInstance()->WriteCheckPoint(info);
	CheckPoint::g_checkpoint_cs.Leave();
}

void CDut::add_assembly(const char* name, const char* dir)
{
	CAssemblyInfo info;

	info.manufacturer = "PSZ";
	info.location = "Suzhou";
	info.work_order = "work_order";
	info.device_config = "device_config";
	info.parent_serial_number = m_isn;
	info.parent_gpn = "pg01";
	info.parent_mpn = "pm01";
	info.child_serial_number = m_isn;
	info.child_lot_number = m_isn;
	info.child_gpn = "cm01";
	info.child_mpn = "cm01";
	info.child_quantity;
	info.child_location;
	info.child_part_type;
	info.station_name = CConfig::getInstance()->cfg_station_id.c_str();
	info.station_id = CConfig::getInstance()->cfg_device_id.c_str();
	info.station_type = "TEST";
	info.data_time;
	info.build_phase = CConfig::getInstance()->cfg_run_stage;

	Assembly::g_assembly_cs.Enter();
	CAssembly::getInstance()->SetPathName(name, dir);
	CAssembly::getInstance()->WriteCAssembly(info);
	Assembly::g_assembly_cs.Leave();
}

void CDut::add_components(const char* name, const char* dir)
{
	CComponentsInfo info;

	info.manufacturer = "PSZ";
	info.location = "Suzhou";
	info.gpn = "g01";
	info.mpn = "n01";
	info.serial_number = m_isn;
	info.batch_name;
	info.date_code;
	info.part_description = "TOP HOUSING";
	info.part_type;
	info.part_rerision;
	info.quantity;
	info.supplier;

	Components::g_components_cs.Enter();
	CComponents::getInstance()->SetPathName(name, dir);
	CComponents::getInstance()->WriteCComponents(info);
	Components::g_components_cs.Leave();
}

int CDut::popup_input_form(const char* title1, const char* reg1, const char* title2, const char* reg2, const char* title3, const char* reg3, string& data1, string& data2, string& data3)
{
	HANDLE event;

	g_popup_input_cs.Enter();

	event = CreateEvent(NULL, TRUE, FALSE, NULL);
	ResetEvent(event);

	m_ui->PopupInputForm(event, title1, reg1, title2, reg2, title3, reg3);

	WaitForSingleObject(event, INFINITE);
	CloseHandle(event);

	data1 = g_data1;
	data2 = g_data2;
	data3 = g_data3;

	g_popup_input_cs.Leave();

	return 0;
}

int CDut::get_dutid(string& dutid)
{
	int ret = RET_FAIL;
	string dos_ret;
	string dev_path;
	vector<string> lines;
	vector<string> dutids;
	vector<string> vid_pid;
	size_t pos;
	string loc_info;

	m_dos.Send("adb.exe devices", dos_ret, 6000);
	m_rdlog->WriteLogf(" adb.exe devices\n%s\n", dos_ret.c_str());

	StringToken(dos_ret.c_str(), lines, "\r\n");
	for (std::vector<string>::iterator it = lines.begin(); it != lines.end(); ++it)
	{
		pos = it->find("\tdevice");
		if (pos != string::npos)
			dutids.push_back(it->substr(0, pos));
	}

	dev_path = m_config["DevicePath"].asString();

	vid_pid.push_back("VID_05C6&PID_9015");
	vid_pid.push_back("VID_05C6&PID_9091");

	dutid = "";
	for (std::vector<string>::iterator it = dutids.begin(); it != dutids.end(); ++it)
	{
		for (std::vector<string>::iterator it2 = vid_pid.begin(); it2 != vid_pid.end(); ++it2)
		{
			get_usb_loc_info(it2->c_str(), it->c_str(), loc_info);
			if (loc_info.compare(dev_path) == 0)
			{
				dutid = *it;
				ret = RET_SUCCESS;
				m_rdlog->WriteLogf(" DUT id: %s\n", dutid.c_str());
				break;
			}
		}
		if (dutid.length() != 0)
			break;
	}

	return ret;
}

int CDut::get_usb_loc_info(const char* vid_pid, const char* sub, string& loc_info)
{
	HKEY hKey;
	DWORD type = REG_SZ;
	char buffer[128];
	DWORD size = _countof(buffer);

	sprintf_s(buffer, "system\\currentcontrolset\\enum\\USB\\%s\\%s", vid_pid, sub);
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, buffer, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		RegQueryValueExA(hKey, "LocationInformation", NULL, &type, (LPBYTE)&buffer, &size);
		RegCloseKey(hKey);
		loc_info = buffer;
	}

	return 0;
}

int CDut::get_dutid2(string& dutid)
{
	string dev_path;

	dev_path = m_config["DevicePath"].asString();

	int ret = CUsbTree::getInstance()->GetAdbDeviceId(dev_path.c_str(), dutid);

	return ret;
}

int CDut::get_dutcomport(string& comport)
{
	string dev_path;

	dev_path = m_config["DevicePath"].asString();

	int ret = CUsbTree::getInstance()->GetComPort(dev_path.c_str(), comport);

	return ret;
}

int CDut::adb_command(const char* cmd, string& retval, int timeout)
{
	int ret = RET_FAIL;
	string adb_cmd = "adb.exe -s " + m_dut_id + " " + cmd;

	g_adb_cmd_cs.Enter();
	ret = m_dos.Send(adb_cmd.c_str(), retval, timeout);
	if ((retval.find("more than one device") != string::npos) || (retval.find("device unauthorized") != string::npos))
	{
		m_rdlog->WriteLogf(" adb result:%s", retval.c_str());
		m_dos.Send("adb.exe kill-server", retval, 500);
		::Sleep(1000);
		ret = m_dos.Send(adb_cmd.c_str(), retval, timeout + 5000);
	}
	g_adb_cmd_cs.Leave();

	//if ((retval.find("error: no devices") != string::npos) || (retval.find("error: more than one device") != string::npos) || (retval.find("error: device") != string::npos) || (retval.find("error: connect failed:") != string::npos))
	if (retval.find("error:") != string::npos)
	{
		ret = RET_FAIL;
	}

	if (retval.find("Android Debug Bridge version") != string::npos)
	{
		retval.erase(70);
		ret = RET_FAIL;
	}

	return ret;
}

int CDut::adb_command(const char* cmd, string& retval, const char* tmnl, int wait, int timeout)
{
	int ret = RET_FAIL;
	string adb_cmd = "adb.exe -s " + m_dut_id + " " + cmd;

	g_adb_cmd_cs.Enter();
	ret = m_dos.Send(adb_cmd.c_str(), retval, tmnl, wait, timeout);
	if ((retval.find("more than one device") != string::npos) || (retval.find("device unauthorized") != string::npos))
	{
		m_rdlog->WriteLogf(" adb result:%s", retval.c_str());
		m_dos.Send("adb.exe kill-server", retval, 500);
		::Sleep(1000);
		ret = m_dos.Send(adb_cmd.c_str(), retval, tmnl, wait, timeout + 5000);
	}
	g_adb_cmd_cs.Leave();

	//if ((retval.find("error: no devices") != string::npos) || (retval.find("error: more than one device") != string::npos) || (retval.find("error: device") != string::npos) || (retval.find("error: connect failed:") != string::npos))
	if (retval.find("error:") != string::npos)
	{
		ret = RET_FAIL;
	}

	if (retval.find("Android Debug Bridge version") != string::npos)
	{
		retval.erase(70);
	}

	return ret;
}

int CDut::fastboot_command(const char* cmd, string& retval, int timeout)
{
	int ret = RET_FAIL;
	string fastboot_cmd = "fastboot.exe -s " + m_dut_id + " " + cmd;

	//g_adb_cmd_cs.Enter();
	ret = m_dos.Send(fastboot_cmd.c_str(), retval, timeout);
	//g_adb_cmd_cs.Leave();

	return ret;
}

int CDut::fastboot_command(const char* cmd, string& retval, const char* tmnl, int wait, int timeout)
{
	int ret = RET_FAIL;
	string fastboot_cmd = "fastboot.exe -s " + m_dut_id + " " + cmd;

	//g_adb_cmd_cs.Enter();
	ret = m_dos.Send(fastboot_cmd.c_str(), retval, tmnl, wait, timeout);
	//g_adb_cmd_cs.Leave();

	return ret;
}

int CDut::reset_usb_hub()
{
	string cmd_result;

	g_adb_cmd_cs.Enter();
	m_dos.Send("adb.exe kill-server", cmd_result, 500);
	::Sleep(1000);
	m_rdlog->WriteLog(" adb.exe kill-server\n sleep 1 sec\n devcon.exe restart *ROOT_HUB20*\n sleep 10 sec\n");

	m_dos.Send("devcon.exe restart *ROOT_HUB20*", cmd_result, 2500);
	if (cmd_result.find("No devices restarted") != string::npos)
		m_dos.Send("devcon.exe restart *ROOT_HUB30*", cmd_result, 2500);

	::Sleep(10000);
	g_adb_cmd_cs.Leave();

	return 0;
}

int CDut::get_value_from_sysenv(const char* data, const char* name, char* value)
{
	const char* p = NULL;
	const char* q = NULL;
	char			temp[512] = { "FAIL" };

	p = strstr(data, name);
	if (p != NULL)
	{
		p = p + strlen(name);
		q = strstr(p, "\r");
	}
	if ((q != NULL) && (q != p))
	{
		strncpy_s(temp, p, q - p);
		temp[q - p] = 0;
		strcpy_s(value, sizeof(temp), temp);
		return 0;
	}

	strcpy_s(value, strlen(temp) + 1, temp);
	return -1;
}

int CDut::get_data_from_isn(const char* isn, int start, int len, char* data)
{
	strncpy_s(data, 32, isn + start, len);
	data[len] = 0;

	return 0;
}


int CDut::regular(string src, const Json::Value& param, string& out)
{
	int ret = S_FALSE;
	bool reg_enable = false;
	string reg_rule;
	int reg_catch = -1;
	std::tr1::regex	rx;
	smatch reg_result;

	reg_enable = ParamBool(param, "reg_enable", false);
	ParamStr(param, "reg_rule", reg_rule, "");
	if (param.isMember("reg_catch"))
		reg_catch = ParamInt(param, "reg_catch", -1);

	if (reg_enable == true)
	{
		try
		{
			rx.assign(reg_rule, regex_constants::icase);
			if (regex_search(src, reg_result, rx) == true)
			{
				for (unsigned int n = 0; n < reg_result.size(); n++)
					output_debug("reg_result[%d]:%s", n, reg_result[n].str().c_str());

				if ((reg_catch >= 0) && (reg_catch < (int)reg_result.size()))
					out = reg_result[reg_catch].str();
				else
					out = "PASS";

				ret = S_OK;
			}
		}
		catch (std::regex_error& e)
		{
			out = "FAIL";
			m_rdlog->WriteLogf(" regex_error caught:%s\n", e.what());
		}
	}
	else
	{
		ret = S_OK;
		out = "PASS";
	}

	return ret;
}

int CDut::add_iplas_items()
{
	int ret = RET_FAIL;
	vector<string> getver;
	char temp[32];

	ret = sfis_get_version(m_isn.c_str(), "MO_D", "LINE", "", getver);
	m_producer.AddCsv("Line", CSfisCsv::Pass, (ret == S_OK ? getver[2].c_str() : "NULL"), "", "", "");

	m_producer.AddCsv("Project", CSfisCsv::Pass, CConfig::getInstance()->cfg_project_name, "", "", "");
	m_producer.AddCsv("Model", CSfisCsv::Pass, CConfig::getInstance()->cfg_project_name, "", "", "");
	g_producer_cs.Enter();
	m_producer.AddCsv("ProducerVersion", CSfisCsv::Pass, CProducer::getInstance()->GetProducerVer(), "", "", "");
	g_producer_cs.Leave();
	m_producer.AddCsv("Type", CSfisCsv::Pass, "ONLINE"/*m_check_route_pass == true ? "ONLINE" : "OFFLINE"*/, "", "", "");
	m_producer.AddCsv("Test Status", CSfisCsv::Pass, m_error_code.empty() == true ? "PASS" : "FAIL", "", "", "");
	m_producer.AddCsv("ErrorCode", CSfisCsv::Pass, m_error_code, "", "", "");

	GetDateTimeFormatA(temp, _countof(temp));
	m_producer.AddCsv("CallerSendTime", CSfisCsv::Pass, temp, "", "", "");
	/*g_sfis_cs.Enter(); danger
	m_producer.AddCsv("SFIS message", CSfisCsv::Pass, CSFIS_Api::getInstance()->m_sfis_st.szMessage, "", "", "");
	g_sfis_cs.Leave();*/

	sprintf_s(temp, "%s-%d", CConfig::getInstance()->cfg_device_id.c_str(), m_id_no);
	m_producer.AddCsv("Slot", CSfisCsv::Pass, temp, "", "", "");
	m_producer.AddCsv("Build", CSfisCsv::Pass, CConfig::getInstance()->cfg_run_stage, "", "", "");

	if (m_var[SFIS_MO].asString() != "")
		m_producer.AddCsv("MO", CSfisCsv::Pass, m_var[SFIS_MO].asString(), "", "", "");
	if (m_var[SFIS_CONFIG].asString() != "")
		m_producer.AddCsv("CONFIG", CSfisCsv::Pass, m_var[SFIS_CONFIG].asString(), "", "", "");

	return S_OK;
}

int CDut::upload_iplas(const char* zip_name)
{
	int ret;
	char temp[512];
	string curpath;

	g_producer_cs.Enter();
	Json::Value ext_name = CConfig::getInstance()->cfg_iplas.attached;
	if (ext_name.size() == 0)
	{
		ret = CProducer::getInstance()->SendTsMsg(m_producer.GetAllData());
		m_rdlog->WriteLog(" SendTsMsg()\n");
	}
	else
	{
		GetCurrentPath(curpath);
		sprintf_s(temp, "%s\\%s\\%s", curpath.c_str(), m_id_name.c_str(), zip_name);
		gen_zip(temp, ext_name);
		::Sleep(50);
		strcat_s(temp, ".7z");
		ret = CProducer::getInstance()->SendTsData(temp, m_producer.GetAllData());
		m_rdlog->WriteLog(" SendTsData()\n");
	}
	if (ret != CProducer::Error_Code::ERR_OK)
	{
		m_rdlog->WriteLogf("\n\n Fail! CProducer::getInstance()->SendTsMsg() : %d\n\n", ret);
		m_rdlog->WriteLog(m_producer.GetAllData());
	}
	g_producer_cs.Leave();

	return S_OK;
}

CRS232* CDut::use_comport(const char* friendlyname, RS232_CONFIG* _cfg)
{
	Json::Value cfg;
	RS232_CONFIG port_cfg;
	string new_name = friendlyname;
	char temp[128];
	string port_d, comport = "";

	if (new_name == "SELF_COMPORT")
	{
		new_name = m_var["self_comport"].asString();
	}
	else
	{
		g_comport_cs.Enter();
		CConfig::getInstance()->GetPortByUnit(m_id_name.c_str(), friendlyname, new_name);
		g_comport_cs.Leave();
	}

	if (m_com.find(new_name) == m_com.end())
	{
		if (_cfg == NULL)
		{
			g_comport_cs.Enter();
			CConfig::getInstance()->GetPorts(new_name.c_str(), cfg);
			g_comport_cs.Leave();

			if (!cfg.empty())
			{
				port_cfg.bEnable = cfg["Enable"].asBool();

				if (port_cfg.bEnable == TRUE)
				{
					port_cfg.BaudRate = cfg["Baudrate"].asUInt();
					port_cfg.ByteSize = cfg["ByteSize"].asUInt();
					port_cfg.fBinary = cfg["Binary"].asUInt();
					port_cfg.FlowControl = cfg["FlowControl"].asUInt();
					port_cfg.Parity = cfg["Parity"].asUInt();
					port_cfg.StopBits = cfg["StopBits"].asUInt();

					port_d = cfg["Port"].asString();
					if (port_d.find("-") != string::npos)
					{
						g_comport_cs.Enter();
						int ret = CUsbTree::getInstance()->GetComPort(port_d.c_str(), comport);
						g_comport_cs.Leave();

						if ((ret == S_OK) && (comport.size() != 0))
							port_d = comport.substr(3, 3);
						else
						{
							sprintf_s(temp, " can not find com port from USB chain:%s\n", port_d.c_str());
							m_rdlog->WriteLog(temp);
							::MessageBoxA(g_uiwnd, temp, "MultiTest", MB_OK);
							return NULL;
						}
					}
					port_cfg.iCOM = atoi(port_d.c_str());
					m_com[new_name] = new CRS232(port_cfg);
					CComPortDbg::getInstance()->AddObjRs232(m_com[new_name]);
				}
				else
				{
					sprintf_s(temp, " com name[%s], setting must be true.\n", new_name.c_str());
					m_rdlog->WriteLog(temp);
					::MessageBoxA(g_uiwnd, temp, "MultiTest", MB_OK);
					return NULL;
				}
			}
			else
			{
				sprintf_s(temp, " can not find com name:%s\n", new_name.c_str());
				m_rdlog->WriteLog(temp);
				::MessageBoxA(g_uiwnd, temp, "MultiTest", MB_OK);
				return NULL;
			}
		}
		else
		{
			m_com[new_name] = new CRS232(*_cfg);
			CComPortDbg::getInstance()->AddObjRs232(m_com[new_name]);
		}
	}

	return m_com[new_name];
}

CMyTelnet* CDut::use_telnet(const char* friendlyname)
{
	if (m_telnet.find(friendlyname) == m_telnet.end())
	{
		m_telnet[friendlyname] = new CMyTelnet();
		m_telnet[friendlyname]->AddOutput(this->m_rdlog);
	}

	return m_telnet[friendlyname];
}

CVirtualInstrument* CDut::use_gpibdev(const char* inst)
{
	Json::Value cfg;
	string new_name = inst;
	string type;
	int board = 0;
	int addr = 0;
	int slot = 0;
	string vesa_res_name;
	int fail_code;
	char temp[128];

	CConfig::getInstance()->GetGPIBByUnit(m_id_name.c_str(), inst, new_name);

	if (m_gpib_dev.HaveInit(new_name.c_str()) == false)
	{
		CConfig::getInstance()->GetGPIBs(new_name.c_str(), cfg);

		if (!cfg.empty())
		{
			if (cfg["Enable"].asBool() == true)
			{
				type = cfg["InsType"].asString();
				board = cfg["Board"].asUInt();
				addr = cfg["Addr"].asUInt();
				vesa_res_name = cfg["VESAResourceName"].asString();

				m_gpib_dev.AddOutput(this->m_gpiblog);
				fail_code = m_gpib_dev.Init(new_name.c_str(), type.c_str(), vesa_res_name.c_str(), board, addr);
				if (fail_code != ERROR_SUCCESS)
				{
					sprintf_s(temp, " Failed to init gpib[%s].\n", new_name.c_str());
					m_rdlog->WriteLog(temp);
					::MessageBoxA(g_uiwnd, temp, "MultiTest", MB_OK);
					return NULL;
				}
				m_gpib_dev.use(new_name.c_str())->AddOutput(this->m_gpiblog);
			}
			else
			{
				sprintf_s(temp, " GPIBInst name[%s], setting must be true.\n", new_name.c_str());
				m_rdlog->WriteLog(temp);
				::MessageBoxA(g_uiwnd, temp, "MultiTest", MB_OK);
				return NULL;
			}
		}
		else
		{
			sprintf_s(temp, "can not find inst name:%s", new_name.c_str());
			m_rdlog->WriteLog(temp);
			::MessageBoxA(g_uiwnd, temp, "MultiTest", MB_OK);
			return NULL;
		}
	}

	return m_gpib_dev.use(new_name.c_str());
}
CVirtualInstrument* CDut::use_gpibdev(const char* inst, int& slotOut) ///Hai add 22/08/03
{
	Json::Value cfg;
	string new_name = inst;
	string type;
	int board = 0;
	static int slot = 0;
	int addr = 0;
	string vesa_res_name;
	int fail_code;
	char temp[128];

	CConfig::getInstance()->GetGPIBByUnit(m_id_name.c_str(), inst, new_name);

	if (m_gpib_dev.HaveInit(new_name.c_str()) == false)
	{
		CConfig::getInstance()->GetGPIBs(new_name.c_str(), cfg);

		if (!cfg.empty())
		{
			if (cfg["Enable"].asBool() == true)
			{
				type = cfg["InsType"].asString();
				board = cfg["Board"].asUInt();
				addr = cfg["Addr"].asUInt();
				slot = cfg["Slot"].asUInt();
				vesa_res_name = cfg["VESAResourceName"].asString();

				m_gpib_dev.AddOutput(this->m_gpiblog);
				fail_code = m_gpib_dev.Init(new_name.c_str(), type.c_str(), vesa_res_name.c_str(), board, addr);
				if (fail_code != ERROR_SUCCESS)
				{
					sprintf_s(temp, " Failed to init gpib[%s].\n", new_name.c_str());
					m_rdlog->WriteLog(temp);
					::MessageBoxA(g_uiwnd, temp, "MultiTest", MB_OK);
					return NULL;
				}
				m_gpib_dev.use(new_name.c_str())->AddOutput(this->m_gpiblog);
			}
			else
			{
				sprintf_s(temp, " GPIBInst name[%s], setting must be true.\n", new_name.c_str());
				m_rdlog->WriteLog(temp);
				::MessageBoxA(g_uiwnd, temp, "MultiTest", MB_OK);
				return NULL;
			}
		}
		else
		{
			sprintf_s(temp, "can not find inst name:%s", new_name.c_str());
			m_rdlog->WriteLog(temp);
			::MessageBoxA(g_uiwnd, temp, "MultiTest", MB_OK);
			return NULL;
		}
	}
	slotOut = slot;
	return m_gpib_dev.use(new_name.c_str());
}


void CDut::SuspendTest()
{
	m_ui->EnableButton(true);
	m_ui->UpdateStatus("Suspend");
	m_suspend_event.Reset();
	m_suspend_event.Unlook(INFINITE);
	m_ui->EnableButton(false);
	m_ui->UpdateStatus("Running");
}

void CDut::ResumeTest()
{
	m_suspend_event.Set();
}

int CDut::cmd_init(const char* item, const Json::Value& param)
{
	string station = param["Station"].asString();
	string test_desc = param["TestDesc"].asString();

	Json::Value classes = param["AddClass"];

	char temp[128];
	char datetime[63];
	SYSTEMTIME systime;

	m_test_period.GetTimeA(&systime);
	sprintf_s(datetime, "%.4d-%.2d-%.2d %.2d:%.2d:%.2d", systime.wYear, systime.wMonth, systime.wDay, systime.wHour, systime.wMinute, systime.wSecond);

	size_t pos;
	string f = m_scenario_name;
	pos = f.rfind('.');
	f.erase(pos);
	pos = f.rfind('\\') + 1;
	f = f.substr(pos);

	log_sfis_and_set_info_no_judge("TEST_DATE_TIME", CSfisCsv::Pass, datetime);
	log_sfis_and_set_info_no_judge("STATION_NAME", CSfisCsv::Pass, CConfig::getInstance()->cfg_station_id.c_str());
	log_sfis_and_set_info_no_judge("STATION_SW_VERSION", CSfisCsv::Pass, CToolVer::getInstance()->GetPegalibVer());
	log_sfis_and_set_info_no_judge("SCRIPT_VERSION", CSfisCsv::Pass, f.c_str());
	log_sfis_and_set_info_no_judge("LIMITS_VERSION", CSfisCsv::Pass, CCriteria::getInstance()->GetCriteriaFileName());
	log_sfis_and_set_info_no_judge("RELEASE_VERSION", CSfisCsv::Pass, CToolVer::getInstance()->GetPackageVer());
	log_sfis_and_set_info_no_judge("LINE_NUMBER", CSfisCsv::Pass, CConfig::getInstance()->cfg_line_num.c_str());
	log_sfis_and_set_info_no_judge("FIXTURE_ID", CSfisCsv::Pass, CConfig::getInstance()->cfg_device_id.c_str()/*cfg_fixture_id.c_str()*/);
	log_sfis_and_set_info_no_judge("FIXTURE_INDEX", CSfisCsv::Pass, CConfig::getInstance()->cfg_fixture_index.c_str());
	//log_sfis_and_set_info_no_judge("DEVICE_ID", CSfisCsv::Pass, CConfig::getInstance()->cfg_device_id.c_str());
	log_sfis_and_set_info_no_judge("SLOT_ID", CSfisCsv::Pass, m_id_no);

	g_sfis_cs.Enter();
	strcpy_s(temp, CSFIS_Api::getInstance()->m_sfis_st.szUserID);
	g_sfis_cs.Leave();
	log_sfis_and_set_info_no_judge("USER_ID", CSfisCsv::Pass, temp[0] != 0 ? temp : "Tester");
	//m_sfiscsv->WriteCsv("STATION_MODE", CSfisCsv::Pass, (m_test_mode == TestMode::QTR ? "CONSISTENCY" : "NORMAL"), "N/A", "N/A");
	//log_sfis_and_set_info_no_judge("STATION_MODE", CSfisCsv::Pass, (m_test_mode == TestMode::OnLine ? PATH_ONLINE : PATH_OFFLINE));

	log_sfis_and_set_info_no_judge("STATION_ONLINE", CSfisCsv::Pass, (m_test_mode == TestMode::OnLine ? "1" : "0"));
	//log_sfis_and_set_info_no_judge("SFIS_LOGIN_DB", CSfisCsv::Pass, "PASS");

	if (m_repeat_count == 0)
		strcpy_s(temp, "N/A");
	else
		sprintf_s(temp, "CONSISTENCY_%.4d%.2d%.2d_%.2d%.2d%.2d", systime.wYear, systime.wMonth, systime.wDay, systime.wHour, systime.wMinute, systime.wSecond);

	log_sfis_and_set_info_no_judge("SPC_RUN_ID", CSfisCsv::Pass, temp);
	log_sfis_and_set_info_no_judge("SPC_ITERATION", CSfisCsv::Pass, m_repeat_count);

	m_rdlog->WriteLogf(" %s\n", f.c_str());
	m_rdlog->WriteLogf(" %s\n", CCriteria::getInstance()->GetCriteriaFileName());
	m_rdlog->WriteLogf(" %s\n", CConfig::getInstance()->GetConfigFileName());
	m_rdlog->WriteLogf(" dut id:%d\n name  :%s\n", m_id_no, m_id_name.c_str());


	for (unsigned int i = 0; i < classes.size(); i++)
		m_other_dut.AddSubDut(this, classes[i].asString().c_str());

	m_other_dut.InitTest(param);

	return 0;
}

int CDut::cmd_wait(const char* item, const Json::Value& param)
{
	int msec = 0;

	if (param.isInt())
		msec = param.asInt();
	else
	{
		msec = ParamInt(param, "time", 0);
		log_sfis_and_set_info_no_judge(item, CSfisCsv::Pass, "N/A");
	}

	::Sleep(msec);

	return 0;
}

int CDut::cmd_message(const char* item, const Json::Value& param)
{
	int size = 0;
	wchar_t* pwc;
	wstring wmsg, wname, wisn;

	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	wname = converter.from_bytes(m_id_name.c_str());
	wisn = converter.from_bytes(m_isn.c_str());
	if (wname == wisn)
		wmsg = L"[" + wname + L"]\n";
	else
		wmsg = wmsg = L"[" + wname + L"] [" + wisn + L"]\n";

	size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, param.asString().c_str(), -1, NULL, 0);
	if (size != 0)
	{
		pwc = new wchar_t[size + 1];
		MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, param.asString().c_str(), -1, pwc, size);
		wmsg = wmsg + pwc;
		delete pwc;
	}
	else
	{
		size = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, param.asString().c_str(), -1, NULL, 0);
		if (size != 0)
		{
			pwc = new wchar_t[size + 1];
			MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, param.asString().c_str(), -1, pwc, size);
			wmsg = wmsg + pwc;
			delete pwc;
		}
		else
			wmsg = converter.from_bytes(param.asString());
	}

	::MessageBoxW(g_uiwnd, wmsg.c_str(), L"MultiTest", MB_OK);

	return 0;
}

int CDut::cmd_together(const char* item, const Json::Value& param)
{
	CCalcPeriod period;
	auto_ptr<CTheNumber> my_number;
	int expected_count = ParamInt(param, "expected_count", 0);

	m_rdlog->WriteLog(" Waiting...\n");
	period.GetTimeA();

	Together::g_together_cs.Enter();
	if (expected_count == 0)
		my_number = CGoTogether::getInstance()->TakeNumber(m_id_name.c_str());
	else
	{
		my_number = CGoTogether::getInstance()->TakeNumber(m_id_name.c_str(), expected_count);
		m_rdlog->WriteLogf(" expected count:%d\n", expected_count);
	}
	Together::g_together_cs.Leave();
	my_number->Wait();
	::Sleep(50);

	period.GetTimeB();
	m_rdlog->WriteLogf(" take me %4.3fsec.\n Let's go!\n", (float)period.GetDiff() / 1000);

	return 0;
}

int CDut::cmd_only_one(const char* item, const Json::Value& param)
{
	bool is_only_one = param.asBool();

	if (is_only_one)
		g_only_one_cs.Enter();
	else
		g_only_one_cs.Leave();

	return 0;
}

int CDut::cmd_run_once(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	auto_ptr<CTheNumber> my_number;
	string item_name;
	Json::Value params;

	Together::g_together_cs.Enter();
	my_number = CGoTogether::getInstance()->TakeNumber(m_id_name.c_str());

	if (my_number->IsFirst())
	{
		m_rdlog->WriteLog(" The following process is run once\n");

		item_name = param.getMemberNames()[0];
		params = param[item_name];
		ret = run_script_command(item_name, params);

		g_datapool_cs.Enter();
		CDataPool::getInstance()->m_datapool[LAST_REC] = m_sfiscsv->GetLastRecord();
		g_datapool_cs.Leave();
	}
	else
	{
		m_rdlog->WriteLog(" by pass.\n");

		g_datapool_cs.Enter();
		m_sfiscsv->WriteCsv(CDataPool::getInstance()->m_datapool[LAST_REC].asString().c_str());
		g_datapool_cs.Leave();
	}

	Together::g_together_cs.Leave();
	my_number->Wait();
	::Sleep(50);

	return ret;
}

int CDut::cmd_end_test(const char* item, const Json::Value& param)
{
	char temp[512];
	int fail_count = 0;
	string fail_items;
	string test_item_without_error_code;
	char datetime[64];
	char totaltime[63];
	char new_file_name[128];
	SYSTEMTIME systime;
	int final_ret = 0;

	run_sub_script_command(param);

	log_sfis_and_set_info_no_judge("STATION_MODE", CSfisCsv::Pass, (m_route_status != ROUTE_UNKNOW ? PATH_ONLINE : PATH_OFFLINE));

	g_sfis_cs.Enter();////
	//CSFIS_Api::getInstance()->GenerateErrorCode(m_sfiscsv->GetCsvFullName(), m_error_code);


	if (!CConfig::getInstance()->cfg_new_sfis_dll)
	{
		CSFIS_Api::getInstance()->GenerateErrorCode(m_sfiscsv, m_error_code);
		CSFIS_Api::getInstance()->ListItemsWithoutErrorCode(m_sfiscsv, test_item_without_error_code);
	}
	else
	{
		CSFISLibApi::getInstance()->GenerateErrorCode(m_sfiscsv, m_error_code);
		CSFISLibApi::getInstance()->ListItemsWithoutErrorCode(m_sfiscsv, test_item_without_error_code);
	}

	if (!test_item_without_error_code.empty())
		m_rdlog->WriteLogfEX(WarningLevel, "\n The following test items are no error code\n %s\n", test_item_without_error_code.c_str());

	// priority error item
	// add code here
	/*string errcode;
	string erritem;
	string ei = CSFIS_Api::getInstance()->m_sfis_st.szErrorItem;
	CConfig::getInstance()->GetPriorotyErrorCode(CSFIS_Api::getInstance()->m_sfis_st.szErrorItem, erritem, errcode);*/

	//m_check_route_pass = true;  ///Hai add 22/07/28
	if (m_exit_test_and_no_sfis == false)
	{
		if (m_check_route_pass == true)
		{
			final_ret = sfis_test_result();
			m_var["final_ret"] = final_ret;

			if (final_ret == 0)
			{
				log_sfis_and_set_info_no_judge("SFIS_UPLOAD_TEST_RESULT", CSfisCsv::Pass, "PASS");
				//log_sfis_and_set_info_no_judge("SFIS_LOGOUT_DB", CSfisCsv::Pass, "PASS");
			}
			else
			{
				log_sfis_and_set_info_no_judge("SFIS_UPLOAD_TEST_RESULT", CSfisCsv::Pass, "FAIL");
				//log_sfis_and_set_info_no_judge("SFIS_LOGOUT_DB", CSfisCsv::Pass, "PASS");
			}
		}
		else
		{
			log_sfis_and_set_info_no_judge("SFIS_UPLOAD_TEST_RESULT", CSfisCsv::Pass, "PASS");
			//log_sfis_and_set_info_no_judge("SFIS_LOGOUT_DB", CSfisCsv::Pass, "PASS");
		}
	}

	g_sfis_cs.Leave();////

	fail_count = m_sfiscsv->GetFailCount();
	sprintf_s(temp, "%d", fail_count);
	log_sfis_and_set_info_no_judge("TEST_FAIL_ITEM_QTY", CSfisCsv::Pass, temp);

	m_sfiscsv->GetFailItems(fail_items);
	log_sfis_and_set_info_no_judge("TEST_FAILURES", CSfisCsv::Pass, fail_items.c_str());

	m_test_period.GetTimeB(&systime);
	sprintf_s(datetime, "%.4d-%.2d-%.2d %.2d:%.2d:%.2d", systime.wYear, systime.wMonth, systime.wDay, systime.wHour, systime.wMinute, systime.wSecond);
	sprintf_s(totaltime, "%4.3f", (float)m_test_period.GetDiff() / 1000);

	if (m_error_code.empty() == true)
	{
		log_sfis_and_set_info_no_judge("OVERALL_TEST_RESULT", CSfisCsv::Pass, "PASS");
		sprintf_s(new_file_name, "%s_%.4d%.2d%.2d_%.2d%.2d%.2d", m_isn.c_str(), systime.wYear, systime.wMonth, systime.wDay, systime.wHour, systime.wMinute, systime.wSecond);
	}
	else
	{
		log_sfis_and_set_info_no_judge("OVERALL_TEST_RESULT", CSfisCsv::Fail, "FAIL");
		sprintf_s(new_file_name, "%s_%s_%.4d%.2d%.2d_%.2d%.2d%.2d", m_isn.c_str(), m_error_code.c_str(), systime.wYear, systime.wMonth, systime.wDay, systime.wHour, systime.wMinute, systime.wSecond);
	}

	log_sfis_and_set_info_no_judge("TEST_END_TIME", CSfisCsv::Pass, datetime);
	log_sfis_and_set_info_no_judge("TOTAL_TEST_TIME", CSfisCsv::Pass, totaltime);
	m_rdlog->WriteLogf(" TOTAL_TEST_TIME: %s sec\n", totaltime);

	if (final_ret == 0)
	{
		if (m_error_code.empty() == true)
		{
			m_ui->UpdateStatus("Pass");
		}
		else
		{
			m_ui->UpdateStatus(m_error_code.c_str());
			//m_ui->SetTextProgress(m_sfiscsv->GetFirstFailItem());
		}
	}
	else
	{
		m_ui->UpdateStatus("SFIS:TestResult fail!");
	}

	// alert light

	m_rdlog->Rename(new_file_name);
	m_sfiscsv->Rename(new_file_name);
	m_gpiblog->Rename(new_file_name);

	if (CConfig::getInstance()->cfg_iplas.enable && m_check_route_pass/**/)
	{
		add_iplas_items();
		upload_iplas(new_file_name);
	}

	create_backup_path();

	move_all_files_to(m_local_path.c_str());
	if (CConfig::getInstance()->cfg_server_log.enable_save == true)
	{
		int flag = 0;
		if (move_all_files_to(m_server_path.c_str(), CConfig::getInstance()->cfg_server_log.no_debug_log_when_pass) == FALSE)
			flag = 1;
		record_file_status_list(m_sfiscsv->m_file_name.c_str(), flag);
	}

	return 0;
}

int CDut::cmd_sfis_check_route(const char* item, const Json::Value& param)
{
	string msg = "";

	if (m_test_mode == OnLine)
	{
		if (m_route_status == ROUTE_UNKNOW)
		{
			g_sfis_cs.Enter();
			sfis_check_route(msg);
			g_sfis_cs.Leave();
		}
		//m_rdlog->WriteLog(msg.c_str());

		if (m_route_status == ROUTE_OK)
			log_sfis_and_set_info_no_judge(item, CSfisCsv::Pass, "PASS");
		else
		{
			Together::g_together_cs.Enter();
			CGoTogether::getInstance()->Remove(m_id_name.c_str());
			Together::g_together_cs.Leave();

			log_sfis_and_set_info_no_judge(item, CSfisCsv::Fail, "FAIL");
			m_exit_test_and_no_sfis = true;
			msg = "[" + m_id_name + "] [" + m_isn + "]\n" + msg;
			::MessageBoxA(g_uiwnd, msg.c_str(), "Warning!", MB_OK);
		}
	}
	else
		log_sfis_and_set_info_no_judge(item, CSfisCsv::Pass, "PASS");

	create_backup_path();

	return 0;
}

int CDut::cmd_sfis_get_previous_result(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	bool white_list_enable;
	string white_list_errcode;
	bool black_list_enable;
	string black_list_errcode;
	vector<string> getver;
	vector<string> fields;
	string errcode;

	ret = sfis_get_previous_result(m_isn.c_str(), getver);
	if ((ret == RET_SUCCESS) && (getver.size() == 4))
	{
		StringToken(getver[2].c_str(), fields, ";");
		errcode = fields[3];
		m_rdlog->WriteLogf(" previous_result:%s\n errcode:%s\n", getver[2].c_str(), fields[3].c_str());
	}
	else
	{
		m_exit_test_and_no_sfis = true;
		ret = RET_FAIL;
	}

	if (ret == RET_SUCCESS)
	{
		if (param.isMember("white_list_enable"))
		{
			white_list_enable = param["white_list_enable"].asBool();
			white_list_errcode = param["white_list_errcode"].asString();

			if (white_list_enable)
				if (white_list_errcode.find(errcode) != string::npos)
					m_rdlog->WriteLog(" errcode is in white_list\n");
				else
				{
					m_rdlog->WriteLog(" errcode is not in white_list\n");
					m_exit_test_and_no_sfis = true;
					ret = RET_FAIL;
				}
		}

		if (param.isMember("black_list_enable"))
		{
			black_list_enable = param["black_list_enable"].asBool();
			black_list_errcode = param["black_list_errcode"].asString();

			if (black_list_enable)
				if (black_list_errcode.find(errcode) != string::npos)
				{
					m_rdlog->WriteLog(" errcode is in black_list\n");
					m_exit_test_and_no_sfis = true;
					ret = RET_FAIL;
				}
				else
					m_rdlog->WriteLog(" errcode is not in black_list\n");
		}
	}

	if (ret == RET_SUCCESS)
		log_sfis_and_set_info_no_judge(item, CSfisCsv::Pass, "PASS");
	else
		log_sfis_and_set_info_no_judge(item, CSfisCsv::Fail, "FAIL");

	return ret;
}

int CDut::cmd_sfis_get_config(const char* item, const Json::Value& param)
{
	int ret = S_FALSE;
	vector<string> getver;

	ret = sfis_get_version(m_isn.c_str(), "GET_CONFIG", "MO_MEMO", "", getver);

	if ((ret == RET_SUCCESS) && (getver.size() >= 2))
	{
		m_var[SFIS_CONFIG] = getver[2];
		log_sfis_and_set_info_no_judge(item, CSfisCsv::Pass, getver[2].c_str());
	}
	else
		log_sfis_and_set_info_no_judge(item, CSfisCsv::Pass, "SKIP");

	return ret;
}

int CDut::cmd_mac_addr(const char* item, const Json::Value& param)
{
	int ret = -1;
	IP_ADAPTER_INFO adapter[20];
	DWORD buflen = sizeof(adapter);
	DWORD status = GetAdaptersInfo(adapter, &buflen);
	string msg = "can't find the specified mac addr.";
	string ip_addr = param.asString();

	if (status == ERROR_SUCCESS)
	{
		IP_ADAPTER_INFO dummy;
		dummy.Next = adapter;
		PIP_ADAPTER_INFO painfo = &dummy;
		do
		{
			painfo = painfo->Next;
			if (painfo == NULL) break;

			if (_stricmp("auto detect", ip_addr.c_str()) == 0)
			{
				if (painfo->DhcpEnabled == false) continue;
				if (strcmp("0.0.0.0", painfo->IpAddressList.IpAddress.String) == 0) continue;
				if (strcmp("0.0.0.0", painfo->GatewayList.IpAddress.String) == 0) continue;
				char* p1 = painfo->GatewayList.IpAddress.String;
				char* p2 = strchr(painfo->GatewayList.IpAddress.String, '.');
				p2 = strchr(p2 + 1, '.');
				if (strncmp(painfo->IpAddressList.IpAddress.String, painfo->GatewayList.IpAddress.String, p2 - p1) != 0) continue;

				BYTE* p = painfo->Address;
				char mac[32];
				sprintf_s(mac, "%02X:%02X:%02X:%02X:%02X:%02X", p[0], p[1], p[2], p[3], p[4], p[5]);
				m_rdlog->WriteLogf(" mac addr: %s\n", mac);
				log_sfis_and_set_info_no_judge("STATION_MAC", CSfisCsv::Pass, mac);
				ret = ERROR_SUCCESS;
				break;
			}
			else if (strcmp(painfo->GatewayList.IpAddress.String, ip_addr.c_str()) == 0)
			{
				BYTE* p = painfo->Address;
				char mac[32];
				sprintf_s(mac, "%02X:%02X:%02X:%02X:%02X:%02X", p[0], p[1], p[2], p[3], p[4], p[5]);
				m_rdlog->WriteLogf(" mac addr: %s\n", mac);
				log_sfis_and_set_info_no_judge("STATION_MAC", CSfisCsv::Pass, mac);
				ret = ERROR_SUCCESS;
				break;
			}
		} while (painfo != NULL);
	}
	else
	{
		msg = "GetAdaptersInfo() fail!";
	}

	if (ret != ERROR_SUCCESS)
	{
		m_rdlog->WriteLogf(" %s\n", msg.c_str());
		log_sfis_and_set_info_no_judge("STATION_MAC", CSfisCsv::Fail, "FAIL");
	}

	return ret;
}

int CDut::cmd_get_isn_from_ui(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	string item_name;
	string chk_route_isn = PARAM_S("chk_route_isn");
	string data_name = PARAM_S("data_name");

	ParamStr(param, "item_name", item_name, item);

	if (strlen(m_input_data[0]) != 0)
	{
		m_var[data_name] = m_input_data[0];
		m_isn = m_input_data[0];


		if (chk_route_isn == "FATP")
			m_isn_fatp = m_isn;
		else if (chk_route_isn == "MLB")
			m_isn_mlb = m_isn;

		if (!m_isn.empty())
		{
			m_ui->UpdateIsn(m_isn.c_str());
			m_rdlog->Rename(m_isn.c_str());
			m_sfiscsv->Rename(m_isn.c_str());
			m_gpiblog->Rename(m_isn.c_str());

			m_isn_ui = m_isn; // min add
		}

		log_sfis_and_set_info_no_judge(item_name.c_str(), CSfisCsv::Pass, m_input_data[0]);
		ret = RET_SUCCESS;
	}

	return ret;
}

int CDut::cmd_adb_devices(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	unsigned int timeout = param["timeout"].asUInt();
	CCalcPeriod period;
	string adb_result;

	period.GetTimeA();
	do
	{
		g_adb_dev_cs.Enter();
		output_debug("[fox] get_dutid2()++");
		ret = get_dutid2(m_dut_id);
		output_debug("[fox] get_dutid2()--");
		g_adb_dev_cs.Leave();

		if ((ret == RET_SUCCESS) && (m_dut_id.size() != 0))
		{
			ret = adb_command("devices", adb_result);
			m_rdlog->WriteLogf(" result of adb device:%s\n", adb_result.c_str());

			if ((ret == RET_SUCCESS) && (adb_result.find(m_dut_id) != string::npos))
			{
				log_sfis_and_set_info_no_judge("ADB_DEVICES", CSfisCsv::Pass, "PASS");
				m_rdlog->WriteLogf(" adb device id:%s\n", m_dut_id.c_str());
				m_var["adb_device_id"] = m_dut_id;
				break;
			}
			else
				ret = RET_FAIL;
		}
		else
			m_rdlog->WriteLog(" failed to get_dutid()\n");

		::Sleep(799);
		period.GetTimeB();
	} while (period.GetDiff() < timeout);

	if (ret != RET_SUCCESS)
	{
		m_exit_test_and_no_sfis = true;
		m_rdlog->WriteLog(" failed to get id(adb devices)\n");
		log_sfis_and_set_info_no_judge("ADB_DEVICES", CSfisCsv::Fail, "FAIL");
	}

	return ret;
}

int CDut::cmd_fastboot_devices(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	unsigned int timeout = param["timeout"].asUInt();
	CCalcPeriod period;
	string fastboot_result;

	period.GetTimeA();
	do
	{
		g_adb_dev_cs.Enter();
		ret = get_dutid2(m_dut_id);
		g_adb_dev_cs.Leave();

		if ((ret == RET_SUCCESS) && (m_dut_id.size() != 0))
		{
			ret = fastboot_command("devices", fastboot_result);
			m_rdlog->WriteLogf(" result of fastboot device:%s\n", fastboot_result.c_str());

			if ((ret == RET_SUCCESS) && (fastboot_result.find(m_dut_id) != string::npos))
			{
				log_sfis_and_set_info_no_judge(item, CSfisCsv::Pass, "PASS");
				m_rdlog->WriteLogf(" fastboot device id:%s\n", m_dut_id.c_str());
				break;
			}
			else
				ret = RET_FAIL;
		}
		else
		{
			m_rdlog->WriteLog(" failed to get_dutid()\n");
			ret = RET_FAIL;
		}

		::Sleep(799);
		period.GetTimeB();
	} while (period.GetDiff() < timeout);

	if (ret != RET_SUCCESS)
	{
		m_exit_test_and_no_sfis = true;
		m_rdlog->WriteLog(" failed to get id(fastboot devices)\n");
		log_sfis_and_set_info_no_judge(item, CSfisCsv::Fail, "FAIL");
	}

	return ret;
}

int CDut::cmd_get_isn_fatp(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	string item_name = param["item_name"].asString();
	string dut_result;
	string isn;

	ret = adb_command("shell sysenv get aserial#", dut_result);
	m_rdlog->WriteLogf(" dut_result:%s\n", dut_result.c_str());

	if (ret == RET_SUCCESS)
	{
		isn = dut_result.substr(0, dut_result.find("\r"));
		m_isn_fatp = isn;
		m_isn = isn;

		if (!m_isn.empty())
		{
			m_ui->UpdateIsn(m_isn.c_str());
			m_rdlog->Rename(m_isn.c_str());
			m_sfiscsv->Rename(m_isn.c_str());
			m_gpiblog->Rename(m_isn.c_str());
		}

		log_sfis_and_set_info_no_judge(item_name.c_str(), CSfisCsv::Pass, isn.c_str());
	}
	else
	{
		log_sfis_and_set_info_no_judge(item_name.c_str(), CSfisCsv::Fail, "FAIL");
	}

	return ret;
}

int CDut::cmd_get_sysenv_info(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	string kind_of_isn = param["chk_route_isn"].asString();
	string dut_result;
	char value[512];

	ret = adb_command("shell sysenv", dut_result);
	output_debug(dut_result.c_str());
	m_rdlog->WriteLogf(" dump sysenv:%s\n", dut_result.c_str());

	get_value_from_sysenv(dut_result.c_str(), "serial#=", value);
	ret += log_sfis_and_set_info_no_judge("TEST_READ_ISN_FATP", CSfisCsv::Pass, value);
	m_isn_fatp = value;
	m_var["serial#"] = value;

	get_value_from_sysenv(dut_result.c_str(), "mlb#=", value);
	ret += log_sfis_and_set_info_no_judge("TEST_READ_ISN_MLB", CSfisCsv::Pass, value);
	m_isn_mlb = value;
	m_var["mlb#"] = value;

	m_isn.clear();
	m_isn = (kind_of_isn.compare("FATP") == 0) ? m_isn_fatp : m_isn_mlb;

	if (!m_isn.empty())
	{
		m_ui->UpdateIsn(m_isn.c_str());
		m_rdlog->Rename(m_isn.c_str());
		m_sfiscsv->Rename(m_isn.c_str());
		m_gpiblog->Rename(m_isn.c_str());
	}

	get_data_from_isn(m_isn.c_str(), 0, 3, value);
	ret += log_sfis_and_set_info_no_judge("PRODUCT_CODE", CSfisCsv::Pass, value);
	ret += log_sfis_and_set_info_no_judge("PRODUCT_CODE_DESC", CSfisCsv::Pass, "BQ FATP");

	get_data_from_isn(m_isn.c_str(), 0, 2, value);
	ret += log_sfis_and_set_info_no_judge("PRODUCT_NAME", CSfisCsv::Pass, value);
	ret += log_sfis_and_set_info_no_judge("PRODUCT_NAME_DESC", CSfisCsv::Pass, "BQ");

	get_data_from_isn(m_isn.c_str(), 2, 1, value);
	ret += log_sfis_and_set_info_no_judge("PRODUCT_TYPE", CSfisCsv::Pass, value);
	ret += log_sfis_and_set_info_no_judge("PRODUCT_TYPE_DESC", CSfisCsv::Pass, "NA");

	get_data_from_isn(m_isn.c_str(), 3, 1, value);
	ret += log_sfis_and_set_info_no_judge("PRODUCT_VERSION", CSfisCsv::Pass, value);
	ret += log_sfis_and_set_info_no_judge("PRODUCT_VERSION_DESC", CSfisCsv::Pass, "WHITE");

	get_data_from_isn(m_isn.c_str(), 4, 2, value);
	ret += log_sfis_and_set_info_no_judge("PRODUCT_REVISION", CSfisCsv::Pass, value);

	get_data_from_isn(m_isn.c_str(), 6, 2, value);
	ret += log_sfis_and_set_info_no_judge("MFG_LOCATION", CSfisCsv::Pass, value);
	ret += log_sfis_and_set_info_no_judge("MFG_LOCATION_DESC", CSfisCsv::Pass, "PEGATRON_MAINTEK_SUZHOU");

	get_data_from_isn(m_isn.c_str(), 8, 2, value);
	ret += log_sfis_and_set_info_no_judge("MFG_WW", CSfisCsv::Pass, value);

	get_data_from_isn(m_isn.c_str(), 10, 2, value);
	ret += log_sfis_and_set_info_no_judge("MFG_YEAR", CSfisCsv::Pass, value);

	get_value_from_sysenv(dut_result.c_str(), "mlbconfig=", value);
	ret += log_sfis_and_set_info_no_judge("TEST_READ_FACTORY_CONFIG_MLB", CSfisCsv::Pass, value);
	m_var["mlbconfig"] = value;

	get_value_from_sysenv(dut_result.c_str(), "config=", value);
	ret += log_sfis_and_set_info_no_judge("TEST_READ_FACTORY_CONFIG_FATP", CSfisCsv::Pass, value);
	m_var["config"] = value;

	get_value_from_sysenv(dut_result.c_str(), "ledconfig=", value);
	ret += log_sfis_and_set_info_no_judge("TEST_READ_FACTORY_CONFIG_LED", CSfisCsv::Pass, value);
	m_var["ledconfig"] = value;

	/*get_value_from_sysenv(dut_result.c_str(), "hingeconfig=", value);
	ret += log_sfis_and_set_info("TEST_READ_FACTORY_CONFIG_HINGE", value);*/

	get_value_from_sysenv(dut_result.c_str(), "build_event=", value);
	ret += log_sfis_and_set_info_no_judge("BUILD_EVENT", CSfisCsv::Pass, value);

	get_value_from_sysenv(dut_result.c_str(), "build_phase=", value);
	ret += log_sfis_and_set_info_no_judge("BUILD_PHASE", CSfisCsv::Pass, value);

	/*get_value_from_sysenv(dut_result.c_str(), "hinge#=", value);
	ret += log_sfis_and_set_info("TEST_READ_ISN_HINGE", value);*/

	get_value_from_sysenv(dut_result.c_str(), "led#=", value);
	ret += log_sfis_and_set_info_no_judge("TEST_READ_ISN_LED", CSfisCsv::Pass, value);
	m_var["led#"] = value;

	get_value_from_sysenv(dut_result.c_str(), "frontmic3#=", value);
	ret += log_sfis_and_set_info_no_judge("TEST_READ_ISN_FRONT_MIC_3", CSfisCsv::Pass, value);
	m_var["frontmic3#"] = value;

	/*get_value_from_sysenv(dut_result.c_str(), "frontmic6#=", value);
	log_sfis_and_set_info("TEST_READ_ISN_FRONT_MIC_6", value);*/

	get_value_from_sysenv(dut_result.c_str(), "frontmic9#=", value);
	ret += log_sfis_and_set_info_no_judge("TEST_READ_ISN_FRONT_MIC_9", CSfisCsv::Pass, value);
	m_var["frontmic9#"] = value;

	get_value_from_sysenv(dut_result.c_str(), "botmic#=", value);
	ret += log_sfis_and_set_info_no_judge("TEST_READ_ISN_BOTTOM_MIC", CSfisCsv::Pass, value);
	m_var["botmic#"] = value;

	get_value_from_sysenv(dut_result.c_str(), "spk#=", value);
	ret += log_sfis_and_set_info_no_judge("TEST_READ_ISN_SPEAKER", CSfisCsv::Pass, value);
	m_var["spk#"] = value;

	get_value_from_sysenv(dut_result.c_str(), "cam#=", value);
	ret += log_sfis_and_set_info_no_judge("TEST_READ_ISN_CAMERA", CSfisCsv::Pass, value);
	m_var["cam#"] = value;

	get_value_from_sysenv(dut_result.c_str(), "nlmodel=", value);
	ret += log_sfis_and_set_info_no_judge("TEST_READ_MODEL", CSfisCsv::Pass, value);

	/*get_value_from_sysenv(dut_result.c_str(), "clientversion=", value);
	ret += log_sfis_and_set_info("TEST_READ_FW_VERSION_MLB", value);*/

	get_value_from_sysenv(dut_result.c_str(), "ledbin_ring=", value);
	ret += log_sfis_and_set_info_no_judge("TEST_READ_LEDBIN_RING", CSfisCsv::Pass, value);

	get_value_from_sysenv(dut_result.c_str(), "ledbin_status=", value);
	ret += log_sfis_and_set_info_no_judge("TEST_READ_LEDBIN_STATUS", CSfisCsv::Pass, value);

	if (get_value_from_sysenv(dut_result.c_str(), "hwaddr0=", value) == RET_SUCCESS)
		m_var["hwaddr0"] = value;

	if (get_value_from_sysenv(dut_result.c_str(), "hwaddr1=", value) == RET_SUCCESS)
		m_var["hwaddr1"] = value;

	if (get_value_from_sysenv(dut_result.c_str(), "nlWeaveCertificate=", value) == RET_SUCCESS)
		m_var["nlWeaveCertificate"] = value;

	if (get_value_from_sysenv(dut_result.c_str(), "nlWeavePrivateKey=", value) == RET_SUCCESS)
		m_var["nlWeavePrivateKey"] = value;

	if (get_value_from_sysenv(dut_result.c_str(), "nlWeavePairingCode=", value) == RET_SUCCESS)
		m_var["nlWeavePairingCode"] = value;

	if (get_value_from_sysenv(dut_result.c_str(), "nlWeaveProvisioningHash=", value) == RET_SUCCESS)
		m_var["nlWeaveProvisioningHash"] = value;

	if (get_value_from_sysenv(dut_result.c_str(), "pairing_secret=", value) == RET_SUCCESS)
		m_var["pairing_secret"] = value;

	get_value_from_sysenv(dut_result.c_str(), "rel=", value);
	if ((strcmp(value, "FAIL") == 0) || (strcmp(value, "0") == 0))
	{
		strcpy_s(value, "0");
		m_is_rel = false;
	}
	else
	{
		m_is_rel = true;
		m_test_mode = TestMode::QTR;
	}
	create_backup_path();

	ret += log_sfis_and_set_info("REL_STATUS", value);

	return ret;
}

int CDut::cmd_get_sysenv_info_mlb(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	string dut_result;
	char value[512];

	ret = adb_command("shell sysenv", dut_result);
	output_debug(dut_result.c_str());
	m_rdlog->WriteLogf(" dump sysenv:%s\n", dut_result.c_str());

	get_value_from_sysenv(dut_result.c_str(), "mlb#=", value);
	ret += log_sfis_and_set_info_no_judge("TEST_READ_ISN_MLB", CSfisCsv::Pass, value);
	m_isn_mlb = value;
	m_var["mlb#"] = value;

	m_isn.clear();
	m_isn = m_isn_mlb;

	if (!m_isn.empty())
	{
		m_ui->UpdateIsn(m_isn.c_str());
		m_rdlog->Rename(m_isn.c_str());
		m_sfiscsv->Rename(m_isn.c_str());
		m_gpiblog->Rename(m_isn.c_str());
	}

	get_data_from_isn(m_isn.c_str(), 0, 3, value);
	ret += log_sfis_and_set_info_no_judge("PRODUCT_CODE", CSfisCsv::Pass, value);
	ret += log_sfis_and_set_info_no_judge("PRODUCT_CODE_DESC", CSfisCsv::Pass, "BQ MLB");

	get_data_from_isn(m_isn.c_str(), 0, 2, value);
	ret += log_sfis_and_set_info_no_judge("PRODUCT_NAME", CSfisCsv::Pass, value);
	ret += log_sfis_and_set_info_no_judge("PRODUCT_NAME_DESC", CSfisCsv::Pass, "BQ");

	get_data_from_isn(m_isn.c_str(), 2, 1, value);
	ret += log_sfis_and_set_info_no_judge("PRODUCT_TYPE", CSfisCsv::Pass, value);
	ret += log_sfis_and_set_info_no_judge("PRODUCT_TYPE_DESC", CSfisCsv::Pass, "NA");

	get_data_from_isn(m_isn.c_str(), 3, 1, value);
	ret += log_sfis_and_set_info_no_judge("PRODUCT_VERSION", CSfisCsv::Pass, value);
	ret += log_sfis_and_set_info_no_judge("PRODUCT_VERSION_DESC", CSfisCsv::Pass, "WHITE");

	get_data_from_isn(m_isn.c_str(), 4, 2, value);
	ret += log_sfis_and_set_info_no_judge("PRODUCT_REVISION", CSfisCsv::Pass, value);

	get_data_from_isn(m_isn.c_str(), 6, 2, value);
	ret += log_sfis_and_set_info_no_judge("MFG_LOCATION", CSfisCsv::Pass, value);
	ret += log_sfis_and_set_info_no_judge("MFG_LOCATION_DESC", CSfisCsv::Pass, "PEGATRON_MAINTEK_SUZHOU");

	get_data_from_isn(m_isn.c_str(), 8, 2, value);
	ret += log_sfis_and_set_info_no_judge("MFG_WW", CSfisCsv::Pass, value);

	get_data_from_isn(m_isn.c_str(), 10, 2, value);
	ret += log_sfis_and_set_info_no_judge("MFG_YEAR", CSfisCsv::Pass, value);

	get_value_from_sysenv(dut_result.c_str(), "mlbconfig=", value);
	ret += log_sfis_and_set_info_no_judge("TEST_READ_FACTORY_CONFIG_MLB", CSfisCsv::Pass, value);
	m_var["mlbconfig"] = value;

	get_value_from_sysenv(dut_result.c_str(), "build_event=", value);
	ret += log_sfis_and_set_info_no_judge("BUILD_EVENT", CSfisCsv::Pass, value);

	get_value_from_sysenv(dut_result.c_str(), "build_phase=", value);
	ret += log_sfis_and_set_info_no_judge("BUILD_PHASE", CSfisCsv::Pass, value);

	get_value_from_sysenv(dut_result.c_str(), "nlmodel=", value);
	ret += log_sfis_and_set_info_no_judge("TEST_READ_MODEL", CSfisCsv::Pass, value);

	get_value_from_sysenv(dut_result.c_str(), "rel=", value);
	if ((strcmp(value, "FAIL") == 0) || (strcmp(value, "0") == 0))
	{
		strcpy_s(value, "0");
		m_is_rel = false;
	}
	else
	{
		m_is_rel = true;
		m_test_mode = TestMode::QTR;
	}
	create_backup_path();

	ret += log_sfis_and_set_info("REL_STATUS", value);

	return ret;
}

int CDut::cmd_adb_command(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	string item_name = param["item_name"].asString();
	string reg_rule;
	int reg_catch = -1;
	bool reg_enable = false;
	string adb_cmd = param["dut_cmd"].asString();
	string adb_result;
	std::tr1::regex	rx;
	smatch reg_result;
	string value = "FAIL";

	m_rdlog->WriteLogf(" adb_cmd:%s\n", adb_cmd.c_str());
	ret = adb_command(adb_cmd.c_str(), adb_result);
	m_rdlog->WriteLogf(" adb_result:%s<:)\n", adb_result.c_str());

	if (ret == RET_SUCCESS)
	{
		if (param.isMember("reg_enable"))
		{
			reg_enable = param["reg_enable"].asBool();
			reg_rule = param["reg_rule"].asString();
			if (param.isMember("reg_catch"))
				reg_catch = param["reg_catch"].asInt();
		}

		if (reg_enable == true)
		{
			try
			{
				rx.assign(reg_rule, regex_constants::icase);
				if (regex_search(adb_result, reg_result, rx) == true)
				{
					for (unsigned int n = 0; n < reg_result.size(); n++)
						output_debug("reg_result[%d]:%s", n, reg_result[n].str().c_str());

					if ((reg_catch >= 0) && (reg_catch < (int)reg_result.size()))
						value = reg_result[reg_catch].str();
					else
						value = "PASS";
				}
				else
				{
					ret = RET_FAIL;
				}
			}
			catch (std::regex_error& e)
			{
				ret = RET_FAIL;
				value = "FAIL";
				m_rdlog->WriteLogf(" regex_error caught:%s\n", e.what());
			}
		}
		else
			value = "PASS";
	} // 
	log_sfis_and_set_info(item_name.c_str(), value.c_str());
	return ret;
}

int CDut::multi_adb_command(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	string adb_result;

	int reg_catch;
	string reg_rule;
	string cmd_assgin;
	bool reg_enable;
	string dut_cmd;
	string value = "PASS";
	vector<string> cmd_assign_list, value_result;

	string item_name = param["item_name"].asString();
	cmd_assgin = param["cmd_assign"].asString();
	reg_enable = param["reg_enable"].asBool();
	reg_catch = param["reg_catch"].asInt();

	StringToken(cmd_assgin.c_str(), cmd_assign_list, ",", NONE);

	Json::Value cmd_list = param["dut_cmd"];
	Json::Value reg_rule_list = param["reg_rule"];

	for (unsigned int i = 0; i < cmd_list.size(); i++)
	{
		for (unsigned int j = 0; j < cmd_assign_list.size(); j++)
		{
			if (i == stoi(cmd_assign_list[j]))
			{
				value_result.push_back(adb_cmd_by_regex(cmd_list[i].asString().c_str(),
					reg_enable, reg_rule_list[j].asString().c_str(), reg_catch));
			}
			else
			{
				adb_command((cmd_list[i].asString()).c_str(), adb_result, 1000);
				m_rdlog->WriteLogf(" result: %s", adb_result);
			}
		}
	}
	value = value_result[value_result.size() - 1];
	for (unsigned int n = 0; n < value_result.size(); n++)
	{
		if (value_result[n] == "FAIL")
		{
			value = "FAIL";
			break;
		}
	}
	ret = RET_SUCCESS;
	log_sfis_and_set_info(item_name.c_str(), value.c_str());
	return ret;
}

int CDut::check_button_cmd_adb_pic_have_timeout(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	string adb_result, path_pic, out_regex;
	string item_name = param["item_name"].asString();
	string dut_cmd = param["dut_cmd"].asString();
	string pic_name = param["pic_name"].asString();
	string description = param["description"].asString();
	bool reg_enable = param["reg_enable"].asBool();
	string reg_rule = param["reg_rule"].asString();
	int reg_catch = param["reg_catch"].asInt();
	int ui_btn_result;
	int count = 0;
	bool done_check = false;
	GetCurrentPath(path_pic);
	path_pic = path_pic + "\\" + pic_name;

	while (count < 3)
	{
		ui_btn_result = popup_pic_msg_form(path_pic.c_str(), description.c_str(), 1);
		adb_command(dut_cmd.c_str(), adb_result, 1000);
		m_rdlog->WriteLogf(" result: %s", adb_result.c_str());
		regular(adb_result, param, out_regex);
		if (out_regex == "PASS")
		{
			done_check = true;
			break;
		}
		count++;
	}
	if (done_check)
	{
		log_sfis_and_set_info_no_judge(item_name.c_str(), CSfisCsv::Pass, out_regex.c_str());
	}
	else
	{
		log_sfis_and_set_info_no_judge(item_name.c_str(), CSfisCsv::Fail, "FAIL");
	}
	ret = RET_SUCCESS;
	return ret;
}

int CDut::check_ADD_PICTRUE_ITEMS(const char* item, const Json::Value& param) // add by Hai 20220716
{
	int ret = RET_FAIL;

	string item_name = param["item_name"].asString();
	string pic_name = param["pic_name"].asString();
	string description = param["description"].asString();

	int ui_btn_result;
	int count = 0;
	string path_pic;
	GetCurrentPath(path_pic);
	path_pic = path_pic + "\\" + pic_name;
	do
	{
		ui_btn_result = popup_pic_msg_form(path_pic.c_str(), description.c_str(), 2);
		if (ui_btn_result == 6)
		{
			ret = RET_SUCCESS;
			break;
		}
		count++;
	} while (count < 3);
	if (ret == RET_SUCCESS)
		log_sfis_and_set_info_no_judge(item_name.c_str(), CSfisCsv::Pass, "PASS");
	else log_sfis_and_set_info_no_judge(item_name.c_str(), CSfisCsv::Fail, "FAIL");
	return ret;
}

string CDut::adb_cmd_by_regex(const char* cmd, bool reg_enable, string reg_rule, int reg_catch)
{
	string adb_result;
	std::tr1::regex	rx;
	smatch reg_result;
	string value = "FAIL";
	adb_command(cmd, adb_result, 1000);
	m_rdlog->WriteLogf(" adb_result:%s<:)\n", adb_result.c_str());
	if (reg_enable == true)
	{
		try
		{
			rx.assign(reg_rule, regex_constants::icase);
			if (regex_search(adb_result, reg_result, rx) == true)
			{
				for (unsigned int n = 0; n < reg_result.size(); n++)
					m_rdlog->WriteLogf("reg_result[%d]:%s", n, reg_result[n].str().c_str());
				//output_debug("reg_result[%d]:%s", n, reg_result[n].str().c_str());

				if ((reg_catch >= 0) && (reg_catch < (int)reg_result.size()))
					value = reg_result[reg_catch].str();
				else
					value = "PASS";
			}
		}
		catch (std::regex_error& e)
		{
			value = "FAIL";
			m_rdlog->WriteLogf(" regex_error caught:%s\n", e.what());
		}
	}
	else
		value = "PASS";
	return value;
}
/// <summary>
/// Hai add 19/07
/// </summary>
/// <param name="cmd"></param>
/// <param name="reg_enable"></param>
/// <param name="reg_rule"></param>
/// <param name="reg_catch"></param>
/// <returns></returns>
string CDut::hai_cmd_by_regex(const string& cmd, bool reg_enable, string reg_rule, int reg_catch)
{
	//string adb_result;
	std::tr1::regex	rx;
	smatch reg_result;
	string value = "FAIL";
	//adb_command(cmd, adb_result, 1000);
	m_rdlog->WriteLogf(" adb_result:%s<:)\n", cmd.c_str());
	if (reg_enable == true)
	{
		try
		{
			rx.assign(reg_rule, regex_constants::icase);
			if (regex_search(cmd, reg_result, rx) == true)
			{
				for (unsigned int n = 0; n < reg_result.size(); n++)
					m_rdlog->WriteLogf("reg_result[%d]:%s\n", n, reg_result[n].str().c_str());
				//output_debug("reg_result[%d]:%s", n, reg_result[n].str().c_str());

				if ((reg_catch >= 0) && (reg_catch < (int)reg_result.size()))
					value = reg_result[reg_catch].str();
				else
					value = "PASS";
			}
		}
		catch (std::regex_error& e)
		{
			value = "FAIL";
			m_rdlog->WriteLogf(" regex_error caught:%s\n", e.what());
		}
	}
	else
		value = "PASS";
	return value;
}

int CDut::cmd_fastboot_command(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	string item_name = param["item_name"].asString();
	string fastboot_cmd = param["fastboot_cmd"].asString();
	string tmnl = param["tmnl"].asString();
	unsigned int wait = param["wait"].asUInt();
	unsigned int timeout = param["timeout"].asUInt();
	string reg_rule;
	int reg_catch = -1;
	bool reg_enable = false;
	string fastboot_result;
	std::tr1::regex	rx;
	smatch reg_result;
	string value = "FAIL";

	m_rdlog->WriteLogf(" fastboot_cmd:%s\n", fastboot_cmd.c_str());
	ret = fastboot_command(fastboot_cmd.c_str(), fastboot_result, tmnl.c_str(), wait, timeout);
	m_rdlog->WriteLogf(" fastboot_result:%s<:)\n", fastboot_result.c_str());

	if (ret == RET_SUCCESS)
	{
		if (param.isMember("reg_enable"))
		{
			reg_enable = param["reg_enable"].asBool();
			reg_rule = param["reg_rule"].asString();
			if (param.isMember("reg_catch"))
				reg_catch = param["reg_catch"].asInt();
		}

		if (reg_enable == true)
		{
			try
			{
				rx.assign(reg_rule, regex_constants::icase);
				if (regex_search(fastboot_result, reg_result, rx) == true)
				{
					for (unsigned int n = 0; n < reg_result.size(); n++)
						output_debug("reg_result[%d]:%s", n, reg_result[n].str().c_str());

					if ((reg_catch >= 0) && (reg_catch < (int)reg_result.size()))
						value = reg_result[reg_catch].str();
					else
						value = "PASS";
				}
				else
				{
					ret = RET_FAIL;
				}
			}
			catch (std::regex_error& e)
			{
				ret = RET_FAIL;
				value = "FAIL";
				m_rdlog->WriteLogf(" regex_error caught:%s\n", e.what());
			}
		}
		else
		{
			if (fastboot_result.find(tmnl) != string::npos)
				value = "PASS";
		}
	}

	if (ret == RET_SUCCESS)
		log_sfis_and_set_info_no_judge(item_name.c_str(), CSfisCsv::Pass, value.c_str());
	else
		log_sfis_and_set_info_no_judge(item_name.c_str(), CSfisCsv::Fail, value.c_str());

	return ret;
}

int CDut::cmd_fastboot_command2(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	string item_name = param["item_name"].asString();
	string fastboot_cmd = param["fastboot_cmd"].asString();
	string tmnl = param["tmnl"].asString();
	unsigned int wait = param["wait"].asUInt();
	unsigned int timeout = param["timeout"].asUInt();
	string reg_rule;
	int reg_catch = -1;
	bool reg_enable = false;
	string fastboot_result;
	std::tr1::regex	rx;
	smatch reg_result;
	string value = "FAIL";

	if (m_var.isMember("dl_sec_exclude_90pn") && m_var.isMember("90pn"))
	{
		if (m_var["dl_sec_exclude_90pn"].asString().find(m_var["90pn"].asString()) != string::npos)
		{
			m_rdlog->WriteLogf(" 90PN is %s, do not secure-lock or device-info!\n", m_var["90pn"].asString().c_str());
			return ret;
		}
	}

	m_rdlog->WriteLogf(" fastboot_cmd:%s\n", fastboot_cmd.c_str());
	ret = fastboot_command(fastboot_cmd.c_str(), fastboot_result, tmnl.c_str(), wait, timeout);
	m_rdlog->WriteLogf(" fastboot_result:%s<:)\n", fastboot_result.c_str());

	if (ret == RET_SUCCESS)
	{
		if (param.isMember("reg_enable"))
		{
			reg_enable = param["reg_enable"].asBool();
			reg_rule = param["reg_rule"].asString();
			if (param.isMember("reg_catch"))
				reg_catch = param["reg_catch"].asInt();
		}

		if (reg_enable == true)
		{
			try
			{
				rx.assign(reg_rule, regex_constants::icase);
				if (regex_search(fastboot_result, reg_result, rx) == true)
				{
					for (unsigned int n = 0; n < reg_result.size(); n++)
						output_debug("reg_result[%d]:%s", n, reg_result[n].str().c_str());

					if ((reg_catch >= 0) && (reg_catch < (int)reg_result.size()))
						value = reg_result[reg_catch].str();
					else
						value = "PASS";
				}
				else
				{
					ret = RET_FAIL;
				}
			}
			catch (std::regex_error& e)
			{
				ret = RET_FAIL;
				value = "FAIL";
				m_rdlog->WriteLogf(" regex_error caught:%s\n", e.what());
			}
		}
		else
		{
			if (fastboot_result.find(tmnl) != string::npos)
				value = "PASS";
		}
	}

	if (ret == RET_SUCCESS)
		log_sfis_and_set_info_no_judge(item_name.c_str(), CSfisCsv::Pass, value.c_str());
	else
		log_sfis_and_set_info_no_judge(item_name.c_str(), CSfisCsv::Fail, value.c_str());

	return ret;
}

int CDut::cmd_adb_wait_for_device(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	unsigned int timeout = param["timeout"].asUInt();
	CCalcPeriod period;
	string adb_result;

	period.GetTimeA();
	do
	{
		ret = adb_command("devices", adb_result);
		m_rdlog->WriteLogf(" result of adb device:%s\n", adb_result.c_str());

		if ((ret == RET_SUCCESS) && (adb_result.find(m_dut_id) != string::npos))
		{
			log_sfis_and_set_info_no_judge("ADB_DEVICES", CSfisCsv::Pass, "PASS");
			m_rdlog->WriteLogf(" adb device id:%s\n", m_dut_id.c_str());
			break;
		}
		else
			ret = RET_FAIL;

		::Sleep(888);
		period.GetTimeB();
	} while (period.GetDiff() < timeout);


	if (ret != RET_SUCCESS)
	{
		m_exit_test_and_no_sfis = true;
		log_sfis_and_set_info_no_judge("ADB_DEVICES", CSfisCsv::Fail, "FAIL");
	}

	return ret;
}

int CDut::cmd_fastboot_wait_for_device(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	unsigned int timeout = param["timeout"].asUInt();
	CCalcPeriod period;
	string fastboot_result;

	period.GetTimeA();
	do
	{
		ret = fastboot_command("devices", fastboot_result);
		m_rdlog->WriteLogf(" result of fastboot device:%s\n", fastboot_result.c_str());

		if ((ret == RET_SUCCESS) && (fastboot_result.find(m_dut_id) != string::npos))
		{
			log_sfis_and_set_info_no_judge("FASTBOOT_DEVICES", CSfisCsv::Pass, "PASS");
			m_rdlog->WriteLogf(" fastboot device id:%s\n", m_dut_id.c_str());
			break;
		}
		else
			ret = RET_FAIL;

		::Sleep(888);
		period.GetTimeB();
	} while (period.GetDiff() < timeout);


	if (ret != RET_SUCCESS)
	{
		m_exit_test_and_no_sfis = true;
		log_sfis_and_set_info_no_judge("FASTBOOT_DEVICES", CSfisCsv::Fail, "FAIL");
	}

	return ret;
}

int CDut::cmd_fastboot_flash(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	string new_path;
	char fastboot_cmd[128];
	string fastboot_result;
	string item_name = param["item_name"].asString();
	string flash_cmd = param["flash_cmd"].asString();
	unsigned int timeout = param["timeout"].asUInt();
	unsigned int okay = param["okay"].asUInt();
	size_t pos = 0;
	unsigned int okay_cnt = 0;
	int test_cnt = 2;

	if (m_var.isMember("image_path"))
	{
		new_path = m_var["image_path"].asString();
		new_path = new_path + "/";
		size_t pos = flash_cmd.find(" ");
		flash_cmd.insert(pos + 1, new_path);
	}

	for (int n = 0; n < test_cnt; n++)
	{
		sprintf_s(fastboot_cmd, "flash %s", flash_cmd.c_str());
		m_rdlog->WriteLogf(" fastboot_cmd:%s\n", fastboot_cmd);
		ret = fastboot_command(fastboot_cmd, fastboot_result, "total time", 500, timeout);
		m_rdlog->WriteLogf(" fastboot_result:%s<:)\n", fastboot_result.c_str());

		if (ret == RET_SUCCESS)
		{
			pos = fastboot_result.find("sending");
			if (pos != string::npos)
			{
				do
				{
					pos = fastboot_result.find("OKAY", pos + 1);
					if (pos != string::npos)
						okay_cnt++;
				} while (pos != string::npos);
			}

			if (okay_cnt == okay)
				break;
			else
			{
				okay_cnt = 0;
				ret = RET_FAIL;
			}
		}
		::Sleep(555);
	}

	if (ret == RET_SUCCESS)
		log_sfis_and_set_info_no_judge(item_name.c_str(), CSfisCsv::Pass, "PASS");
	else
		log_sfis_and_set_info_no_judge(item_name.c_str(), CSfisCsv::Fail, "FAIL");

	return ret;
}

int CDut::cmd_fastboot_flash2(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	string new_path;
	char fastboot_cmd[128];
	string fastboot_result;
	string item_name = param["item_name"].asString();
	string flash_cmd = param["flash_cmd"].asString();
	unsigned int timeout = param["timeout"].asUInt();
	unsigned int okay = param["okay"].asUInt();
	size_t pos = 0;
	unsigned int okay_cnt = 0;
	int test_cnt = 2;

	if (m_var.isMember("dl_sec_exclude_90pn") && m_var.isMember("90pn"))
	{
		if (m_var["dl_sec_exclude_90pn"].asString().find(m_var["90pn"].asString()) != string::npos)
		{
			m_rdlog->WriteLogf(" 90PN is %s, do not flash!\n", m_var["90pn"].asString().c_str());
			return ret;
		}
	}

	if (m_var.isMember("image_path"))
	{
		new_path = m_var["image_path"].asString();
		new_path = new_path + "/";
		size_t pos = flash_cmd.find(" ");
		flash_cmd.insert(pos + 1, new_path);
	}

	for (int n = 0; n < test_cnt; n++)
	{
		sprintf_s(fastboot_cmd, "flash %s", flash_cmd.c_str());
		m_rdlog->WriteLogf(" fastboot_cmd:%s\n", fastboot_cmd);
		ret = fastboot_command(fastboot_cmd, fastboot_result, "total time", 500, timeout);
		m_rdlog->WriteLogf(" fastboot_result:%s<:)\n", fastboot_result.c_str());

		if (ret == RET_SUCCESS)
		{
			pos = fastboot_result.find("sending");
			if (pos != string::npos)
			{
				do
				{
					pos = fastboot_result.find("OKAY", pos + 1);
					if (pos != string::npos)
						okay_cnt++;
				} while (pos != string::npos);
			}

			if (okay_cnt == okay)
				break;
			else
				ret = RET_FAIL;
		}
		::Sleep(555);
	}

	if (ret == RET_SUCCESS)
		log_sfis_and_set_info_no_judge(item_name.c_str(), CSfisCsv::Pass, "PASS");
	else
		log_sfis_and_set_info_no_judge(item_name.c_str(), CSfisCsv::Fail, "FAIL");

	return ret;
}

int CDut::cmd_fastboot_flash_unlock(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	char fastboot_cmd[128];
	string fastboot_result;
	string item_name = param["item_name"].asString();
	string flash_cmd = param["flash_cmd"].asString();
	unsigned int timeout = param["timeout"].asUInt();
	unsigned int okay = param["okay"].asUInt();
	size_t pos = 0;
	unsigned int okay_cnt = 0;
	int test_cnt = 2;

	for (int n = 0; n < test_cnt; n++)
	{
		sprintf_s(fastboot_cmd, "flash %s%s", flash_cmd.c_str(), m_dut_id.c_str());
		m_rdlog->WriteLogf(" fastboot_cmd:%s\n", fastboot_cmd);
		ret = fastboot_command(fastboot_cmd, fastboot_result, "total time", 500, timeout);
		m_rdlog->WriteLogf(" fastboot_result:%s<:)\n", fastboot_result.c_str());

		if (ret == RET_SUCCESS)
		{
			pos = fastboot_result.find("sending");
			if (pos != string::npos)
			{
				do
				{
					pos = fastboot_result.find("OKAY", pos + 1);
					if (pos != string::npos)
						okay_cnt++;
				} while (pos != string::npos);
			}

			if (okay_cnt == okay)
				break;
			else
				ret = RET_FAIL;
		}
		::Sleep(555);
	}

	if (ret == RET_SUCCESS)
		log_sfis_and_set_info_no_judge(item_name.c_str(), CSfisCsv::Pass, "PASS");
	else
		log_sfis_and_set_info_no_judge(item_name.c_str(), CSfisCsv::Fail, "FAIL");

	return ret;
}

int CDut::cmd_console_cmd(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	string item_name = param["item_name"].asString();
	string reg_rule;
	int reg_catch = -1;
	bool reg_enable = false;
	string console_cmd = param["console_cmd"].asString();
	string console_result;
	std::tr1::regex	rx;
	smatch reg_result;
	string value = "FAIL";

	m_rdlog->WriteLogf(" console_cmd:%s\n", console_cmd.c_str());
	ret = m_dos.Send(console_cmd.c_str(), console_result, 20000);
	m_rdlog->WriteLogf(" console_result:%s<:)\n", console_result.c_str());

	if (ret == RET_SUCCESS)
	{
		if (param.isMember("reg_enable"))
		{
			reg_enable = param["reg_enable"].asBool();
			reg_rule = param["reg_rule"].asString();
			if (param.isMember("reg_catch"))
				reg_catch = param["reg_catch"].asInt();
		}

		if (reg_enable == true)
		{
			try
			{
				rx.assign(reg_rule, regex_constants::icase);
				if (regex_search(console_result, reg_result, rx) == true)
				{
					for (unsigned int n = 0; n < reg_result.size(); n++)
						output_debug("reg_result[%d]:%s", n, reg_result[n].str().c_str());

					if ((reg_catch >= 0) && (reg_catch < (int)reg_result.size()))
						value = reg_result[reg_catch].str();
					else
						value = "PASS";
				}
				else
				{
					ret = RET_FAIL;
				}
			}
			catch (std::regex_error& e)
			{
				ret = RET_FAIL;
				value = "FAIL";
				m_rdlog->WriteLogf(" regex_error caught:%s\n", e.what());
			}
		}
		else
			value = "PASS";
	}

	log_sfis_and_set_info(item_name.c_str(), value.c_str());

	return ret;
}

int CDut::cmd_self_comport(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	unsigned int timeout = param["timeout"].asUInt();
	RS232_CONFIG port_cfg;
	string port_no;
	CCalcPeriod period;

	port_cfg.bEnable = TRUE;
	port_cfg.BaudRate = PARAM_N("Baudrate");
	port_cfg.ByteSize = PARAM_N("ByteSize");
	port_cfg.FlowControl = PARAM_N("FlowControl");
	port_cfg.Parity = PARAM_N("Parity");
	port_cfg.StopBits = PARAM_N("StopBits");
	port_cfg.fBinary = PARAM_N("Binary");

	period.GetTimeA();
	do
	{
		g_adb_dev_cs.Enter();
		output_debug("[fox] cmd_self_comport()++");
		ret = get_dutcomport(m_dut_comport);
		output_debug("[fox] cmd_self_comport()--");
		g_adb_dev_cs.Leave();

		if ((ret == RET_SUCCESS) && (m_dut_comport.size() != 0))
		{
			port_no = m_dut_comport.substr(3, 3);
			port_cfg.iCOM = atoi(port_no.c_str());
			ret = RET_FAIL;

			if (use_comport(m_dut_comport.c_str(), &port_cfg) != NULL)
			{
				ret = use_comport(m_dut_comport.c_str())->Open();
				m_rdlog->WriteLogf(" result of open com port:%d\n", ret);
			}

			if (ret == RET_SUCCESS)
			{
				log_sfis_and_set_info_no_judge("TEST_SELF_COMPORT", CSfisCsv::Pass, "PASS");
				m_rdlog->WriteLogf(" com port is:%s\n", m_dut_comport.c_str());
				m_var["self_comport"] = m_dut_comport;
				break;
			}
			else
				ret = RET_FAIL;
		}
		else
			m_rdlog->WriteLog(" failed to get_dutcomport()\n");

		::Sleep(799);
		period.GetTimeB();
	} while (period.GetDiff() < timeout);

	if (ret != RET_SUCCESS)
	{
		m_exit_test_and_no_sfis = true;
		m_rdlog->WriteLog(" failed to get(or open) com port\n");
		log_sfis_and_set_info_no_judge("TEST_SELF_COMPORT", CSfisCsv::Fail, "FAIL");
	}

	return ret;
}


int CDut::cmd_open_serial(const char* item, const Json::Value& param)
{
	int ret = S_FALSE;
	string port_nickname;

	ParamStr(param, "port_nickname", port_nickname, "");

	ret = use_comport(port_nickname.c_str())->Open();
	m_rdlog->WriteLogf(" open comport(%d)\n", ret);

	if (ret == S_OK)
		log_sfis_and_set_info_no_judge(item, CSfisCsv::Pass, "PASS");
	else
		log_sfis_and_set_info_no_judge(item, CSfisCsv::Fail, "FAIL");

	return ret;
}

int CDut::cmd_serial_command(const char* item, const Json::Value& param)
{
	int ret = S_FALSE;
	bool is_port_open = false;
	string item_name;
	string port_nickname;
	int retry = ParamInt(param, "retry", 0);
	int times = 0;
	string serial_cmd;
	string r_tmnl;
	unsigned int wr_wait;
	unsigned int r_timeout;
	string serial_result = "";
	string reg_result;
	int test_result = S_FALSE;

	ParamStr(param, "item_name", item_name, "");
	ParamStr(param, "port_nickname", port_nickname, "");
	ParamStr(param, "w_cmd", serial_cmd, "");
	serial_cmd = serial_cmd + "\r";
	ParamStr(param, "r_tmnl", r_tmnl, "");
	wr_wait = ParamInt(param, "wr_wait", 10);
	r_timeout = ParamInt(param, "r_timeout", 500);

	do
	{
		if (use_comport(port_nickname.c_str()) != NULL)
		{
			is_port_open = use_comport(port_nickname.c_str())->IsOpen();
			if (!is_port_open)
				ret = use_comport(port_nickname.c_str())->Open();

			m_rdlog->WriteLogf(" serial_cmd(%d):%s\n", ret, serial_cmd.c_str());
			if (r_tmnl == "")
				ret = use_comport(port_nickname.c_str())->WRString(serial_cmd.c_str(), serial_result, 200);
			else
				ret = use_comport(port_nickname.c_str())->WRString(serial_cmd.c_str(), serial_result, r_tmnl.c_str(), wr_wait, r_timeout);
			m_rdlog->WriteLogf(" serial_result(%d):%s<:)\n", ret, serial_result.c_str());

			if (!is_port_open)
				use_comport(port_nickname.c_str())->Close();
		}

		if (ret == S_OK)
			if (param.isMember("reg_enable"))
				ret = regular(serial_result, param, reg_result);

		times++;
		if (ret == S_OK)
			test_result = log_sfis_and_set_info(item_name.c_str(), reg_result.c_str(), times > retry);
		else
			log_sfis_and_set_info_no_judge(item_name.c_str(), CSfisCsv::Fail, "FAIL", times > retry);

	} while (times <= retry && test_result == S_FALSE);


	return ret;
}


int CDut::cmd_test_reboot_dut(const char* item, const Json::Value& param) //jack add
{
	int ret = S_FALSE;
	bool is_port_open = false;
	string item_name;
	string port_nickname;
	int retry = ParamInt(param, "retry", 0);
	int times = 0;
	string serial_cmd;
	string r_tmnl;
	unsigned int wr_wait;
	unsigned int r_timeout;
	string serial_result = "";
	string reg_result;
	int test_result = S_FALSE;

	ParamStr(param, "item_name", item_name, "");
	ParamStr(param, "port_nickname", port_nickname, "");
	ParamStr(param, "w_cmd", serial_cmd, "");
	serial_cmd = serial_cmd + "\r";
	ParamStr(param, "r_tmnl", r_tmnl, "");
	wr_wait = ParamInt(param, "wr_wait", 10);
	r_timeout = ParamInt(param, "r_timeout", 500);

	if (use_comport(port_nickname.c_str()) != NULL)
	{
		is_port_open = use_comport(port_nickname.c_str())->IsOpen();
		if (!is_port_open)
			ret = use_comport(port_nickname.c_str())->Open();
		if ((is_port_open) || (ret == S_OK)) {
			use_comport(port_nickname.c_str())->WRString(serial_cmd.c_str(), serial_result, r_tmnl.c_str(), wr_wait, r_timeout);
			m_rdlog->WriteLogf(" serial_result:%s<:)\n", serial_result.c_str());
			ret = S_FALSE;
		}
		if (serial_result.find(r_tmnl) != std::string::npos)
			ret = S_OK;
		if (!is_port_open)
			use_comport(port_nickname.c_str())->Close();
	}

	if (ret == S_OK)
		log_sfis_and_set_info_no_judge(item_name.c_str(), CSfisCsv::Pass, "PASS");
	else
		log_sfis_and_set_info_no_judge(item_name.c_str(), CSfisCsv::Fail, "FAIL");

	return ret;
}

int CDut::cmd_dut_connect_time(const char* item, const Json::Value& param)  //jack add
{
	int ret = S_FALSE;
	bool is_port_open = false;
	string item_name;
	string port_nickname;
	int times = 0;
	string r_tmnl_1;
	string r_tmnl_2;
	unsigned int wr_wait;
	unsigned int r_timeout;
	string serial_result = "";
	string reg_result;
	int test_result = S_FALSE;
	string serial_cmd;
	std::vector<string> cmd_list;

	bool flag = FALSE;
	DWORD	ta;
	DWORD	tb;
	double delta_time;

	ParamStr(param, "item_name", item_name, "");
	ParamStr(param, "port_nickname", port_nickname, "");
	ParamStr(param, "r_tmnl_1", r_tmnl_1, "");
	ParamStr(param, "r_tmnl_2", r_tmnl_2, "");
	wr_wait = ParamInt(param, "wr_wait", 100);
	r_timeout = ParamInt(param, "r_timeout", 15000);
	serial_cmd = param["w_cmd"].asString();
	serial_cmd = serial_cmd + "\r";
	string cmd_enter = "\r";

	ta = ::GetTickCount();
	if (use_comport(port_nickname.c_str()) != NULL)
	{
		is_port_open = use_comport(port_nickname.c_str())->IsOpen();
		flag = TRUE;
	}
	if (!is_port_open & flag == TRUE)
		ret = use_comport(port_nickname.c_str())->Open();
	if ((is_port_open) || (ret == S_OK)) {
		Sleep(wr_wait);
		ret = use_comport(port_nickname.c_str())->ReadString(serial_result, r_tmnl_1.c_str(), r_timeout); //doc serial den khi gap chuoi 1
		m_rdlog->WriteLogf(" serial_result_1:%s<:)\n", serial_result.c_str());

		if (serial_result.find(r_tmnl_1) != std::string::npos) {
			ret = use_comport(port_nickname.c_str())->WRString(serial_cmd.c_str(), serial_result, r_tmnl_2.c_str(), wr_wait, r_timeout);
			m_rdlog->WriteLogf(" serial_result_2:%s<:)\n", serial_result.c_str());
		}
		if (serial_result.find(r_tmnl_2) != std::string::npos)
			test_result = S_OK;
	}
	if (!is_port_open)
		use_comport(port_nickname.c_str())->Close();
	tb = ::GetTickCount();
	delta_time = (tb - ta) / 1000;
	if (test_result == S_OK)
		test_result = log_sfis_and_set_info(item_name.c_str(), delta_time);
	else
		log_sfis_and_set_info_no_judge(item_name.c_str(), CSfisCsv::Fail, "FAIL");
	return test_result;
}

/*std::ostringstream oss;
oss << std::setw(2) <<
	std::setfill('0') << chanel;
std::string str_chanel = oss.str();
if (brightness < 10) {
	std::string brightness = oss.str();
	serial_cmd = "54 4C 00 01 01 " + str_chanel + " " + brightness + "\r";
}
else
	serial_cmd = "54 4C 00 01 01 " + str_chanel + " " + to_string(brightness) + "\r";*/
int CDut::cmd_control_light_panel(const char* item, const Json::Value& param)  // jack add
{
	int ret = S_FALSE;
	bool is_port_open = false;
	string item_name;
	string port_nickname;
	int retry = ParamInt(param, "retry", 0);
	int times = 0;
	unsigned int wr_wait;
	unsigned int r_timeout;
	unsigned int chanel;
	unsigned int brightness;
	unsigned int machine_id;
	unsigned int main_function;
	string identification1;
	string identification2;
	string serial_result = "";
	string reg_result;
	int test_result = S_FALSE;

	ParamStr(param, "item_name", item_name, "");
	ParamStr(param, "item_name", identification2, "4C");
	ParamStr(param, "port_nickname", port_nickname, "");

	chanel = ParamInt(param, "chanel", 2);
	brightness = ParamInt(param, "brightness", 1);
	identification1 = ParamInt(param, "identification1", 53);
	machine_id = ParamInt(param, "machine_id", 00);
	main_function = ParamInt(param, "main_function", 00);
	
	wr_wait = ParamInt(param, "wr_wait", 10);
	r_timeout = ParamInt(param, "r_timeout", 500);


	char serial_cmd[7];
	serial_cmd[0] = 0x54; // T
	serial_cmd[1] = 0x4C; // L
	serial_cmd[2] = 0x00; // Null
	serial_cmd[3] = 0x01; // Start heading
	serial_cmd[4] = 0x01; // Start heading
	serial_cmd[5] = 0x02; // Start text
	serial_cmd[6] = 0x64;
	do
	{
		if (use_comport(port_nickname.c_str()) != NULL)
		{
			is_port_open = use_comport(port_nickname.c_str())->IsOpen();
			if (!is_port_open)
				ret = use_comport(port_nickname.c_str())->Open();

			m_rdlog->WriteLogf(" serial_cmd(%d):%s\n", ret, serial_cmd);
			//ret = use_comport(port_nickname.c_str())->WRString(serial_cmd.c_str(), serial_result, 200);
			ret = use_comport(port_nickname.c_str())->WriteString(serial_cmd);

			//m_rdlog->WriteLogf(" serial_result(%d):%s<:)\n", ret, serial_result.c_str());

			if (!is_port_open)
				use_comport(port_nickname.c_str())->Close();
		}
		times++;
		if (ret == S_OK)
			log_sfis_and_set_info_no_judge(item_name.c_str(), CSfisCsv::Pass, "PASS");
		else
			log_sfis_and_set_info_no_judge(item_name.c_str(), CSfisCsv::Fail, "FAIL", times > retry);
	} while (times <= retry && test_result == S_FALSE);
	return ret;
}

int CDut::cmd_close_serial(const char* item, const Json::Value& param)
{
	int ret = S_FALSE;
	string port_nickname;

	ParamStr(param, "port_nickname", port_nickname, "");

	ret = use_comport(port_nickname.c_str())->Close();
	m_rdlog->WriteLogf(" close comport(%d)\n", ret);
	log_sfis_and_set_info_no_judge(item, CSfisCsv::Pass, "PASS");

	return ret;
}

int CDut::cmd_get_sysenv_item(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	string item_name = PARAM_S("item_name");
	string key = PARAM_S("key");
	bool pass_fail_only = PARAM_B("pass_fail_only");
	string value = "FAIL";
	CSfisCsv::Status stat = CSfisCsv::Fail;

	if (m_var.isMember(key))
	{
		stat = CSfisCsv::Pass;

		if (pass_fail_only)
			value = "PASS";
		else
			value = m_var[key].asString();
	}
	else
		m_rdlog->WriteLogf(" can not find the key:%s\n", key.c_str());

	ret = log_sfis_and_set_info_no_judge(item_name.c_str(), stat, value.c_str());

	return ret;
}

int CDut::cmd_set_sysenv_item(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	string item_name = PARAM_S("item_name");
	string key = PARAM_S("key");
	string data_name = PARAM_S("data_name");
	string adb_cmd;
	string adb_result;

	if (m_var.isMember(data_name))
	{
		adb_cmd = "shell sysenv set " + key + " " + m_var[data_name].asString() + " && sync && sync";

		m_rdlog->WriteLogf(" adb_cmd:%s\n", adb_cmd.c_str());
		ret = adb_command(adb_cmd.c_str(), adb_result);
		m_rdlog->WriteLogf(" adb_result:%s<:)\n", adb_result.c_str());
	}
	else
	{
		m_rdlog->WriteLogf(" data_name \"%s\" is not member of m_var\n", data_name.c_str());
		ret = RET_FAIL;
	}

	if (ret == RET_SUCCESS)
	{
		adb_cmd = "shell sysenv get " + key;

		m_rdlog->WriteLogf(" adb_cmd:%s\n", adb_cmd.c_str());
		ret = adb_command(adb_cmd.c_str(), adb_result);
		m_rdlog->WriteLogf(" adb_result:%s<:)\n", adb_result.c_str());
	}

	if (ret == RET_SUCCESS)
	{
		if (adb_result.find(m_var[data_name].asString()) == string::npos)
			ret = RET_FAIL;
	}

	if (ret == RET_SUCCESS)
		log_sfis_and_set_info_no_judge(item_name.c_str(), CSfisCsv::Pass, "PASS");
	else
		log_sfis_and_set_info_no_judge(item_name.c_str(), CSfisCsv::Fail, "FAIL");

	return ret;
}

int CDut::cmd_upload_save_item(const char* item, const Json::Value& param)
{
	int ret = RET_SUCCESS;
	bool write_really = param["write_csv_really"].asBool();
	Json::Value params = param["items"];
	string save_item_name;
	string data_name;
	string value;

	for (unsigned int i = 0; i < params.size(); i++)
	{
		save_item_name = params.getMemberNames()[i];
		data_name = params[save_item_name].asString();
		value = m_var[data_name].asString();
		if (value.empty())
		{
			m_rdlog->WriteLogf(" data_name(%s) is empty.\n", data_name.c_str());
			ret = RET_FAIL;
			continue;
		}
		log_sfis_save_item_and_set_info(save_item_name.c_str(), value.c_str(), write_really);
	}

	return ret;
}

int CDut::cmd_input_data_ui(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	string title1 = PARAM_S("title1");
	string title2 = PARAM_S("title2");
	string title3 = PARAM_S("title3");
	string reg1 = PARAM_S("reg1");
	string reg2 = PARAM_S("reg2");
	string reg3 = PARAM_S("reg3");
	string data_name1 = PARAM_S("data_name1");
	string data_name2 = PARAM_S("data_name2");
	string data_name3 = PARAM_S("data_name3");
	string input_value1, input_value2, input_value3;

	popup_input_form(title1.c_str(), reg1.c_str(), title2.c_str(), reg2.c_str(), title3.c_str(), reg3.c_str(), input_value1, input_value2, input_value3);

	if (title1 != "N/A")
	{
		m_var[data_name1] = input_value1;
		m_rdlog->WriteLogf(" data_name(%s):%s\n", data_name1.c_str(), input_value1.c_str());
	}

	if (title2 != "N/A")
	{
		m_var[data_name2] = input_value2;
		m_rdlog->WriteLogf(" data_name(%s):%s\n", data_name2.c_str(), input_value2.c_str());
	}

	if (title3 != "N/A")
	{
		m_var[data_name3] = input_value3;
		m_rdlog->WriteLogf(" data_name(%s):%s\n", data_name3.c_str(), input_value3.c_str());
	}

	log_sfis_and_set_info_no_judge(item, CSfisCsv::Pass, "PASS");

	return ret;
}

int CDut::cmd_telnet_open(const char* item, const Json::Value& param)
{
	int ret = S_FALSE;
	string friendly_name;
	string addr;
	short port;
	string prompt;
	string telnet_result;

	ParamStr(param, "friendly_name", friendly_name, "");
	ParamStr(param, "addr", addr, "");
	port = ParamInt(param, "port", 23);
	ParamStr(param, "prompt", prompt, "");

	ret = use_telnet(friendly_name.c_str())->Connect(addr.c_str(), port);
	if (ret == S_OK)
	{
		::Sleep(100);
		ret = use_telnet(friendly_name.c_str())->SendRecvStr("", telnet_result, 1000, prompt.c_str());
	}

	if (ret == S_OK)
	{
		use_telnet(friendly_name.c_str())->SkipInitScreen(telnet_result);
		m_rdlog->WriteLogf("%s\n", telnet_result.c_str());
	}

	return ret;
}

int CDut::cmd_telnet_command(const char* item, const Json::Value& param)
{
	int ret = S_FALSE;
	string item_name;
	string friendly_name;
	string telnet_cmd;
	string prompt;
	string telnet_result;
	string reg_result;

	ParamStr(param, "item_name", item_name, "");
	ParamStr(param, "friendly_name", friendly_name, "");
	ParamStr(param, "telnet_cmd", telnet_cmd, "");
	telnet_cmd = telnet_cmd + "\n";
	ParamStr(param, "prompt", prompt, "");

	m_rdlog->WriteLogf(" cmd:%s\n", telnet_cmd.c_str());
	ret = use_telnet(friendly_name.c_str())->SendRecvStr(telnet_cmd.c_str(), telnet_result, 1000, prompt.c_str());
	if (ret == S_OK)
	{
		m_rdlog->WriteLogf("%s<:)\n", telnet_result.c_str());
		if (param.isMember("reg_enable"))
			ret = regular(telnet_result, param, reg_result);
	}

	if (ret == S_OK)
		log_sfis_and_set_info(item_name.c_str(), reg_result.c_str());
	else
		log_sfis_and_set_info_no_judge(item_name.c_str(), CSfisCsv::Fail, "FAIL");

	return ret;
}

int CDut::pps_on(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	string Itemname = PARAM_S("Item_Name");
	string GPIBname = PARAM_S("GPIB_Name");

	const char* GPIBnamestr = GPIBname.c_str();

	if (use_gpibdev(GPIBnamestr) != NULL)
	{
		m_rdlog->WriteLogf("PPS On");
		ret = use_gpibdev(GPIBnamestr)->PPS_SET_POWER_ON();
	}

	if (ret == RET_SUCCESS)
		log_sfis_and_set_info_no_judge(Itemname.c_str(), CSfisCsv::Pass, "PASS");
	else
		log_sfis_and_set_info_no_judge(Itemname.c_str(), CSfisCsv::Fail, "FAIL");

	return ret;
}

int CDut::pps_off(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	string Itemname = PARAM_S("Item_Name");
	string GPIBname = PARAM_S("GPIB_Name");

	const char* GPIBnamestr = GPIBname.c_str();

	if (use_gpibdev(GPIBnamestr) != NULL)
	{
		m_rdlog->WriteLogf("PPS Off");
		ret = use_gpibdev(GPIBnamestr)->PPS_SET_POWER_OFF();
	}

	if (ret == RET_SUCCESS)
		log_sfis_and_set_info_no_judge(Itemname.c_str(), CSfisCsv::Pass, "PASS");
	else
		log_sfis_and_set_info_no_judge(Itemname.c_str(), CSfisCsv::Fail, "FAIL");

	return ret;
}

int CDut::pps_set_vol(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	string Itemname = PARAM_S("Item_Name");
	string GPIBname = PARAM_S("GPIB_Name");
	double Voltage = PARAM_N("Voltage");

	const char* GPIBnamestr = GPIBname.c_str();

	if (use_gpibdev(GPIBnamestr) != NULL)
	{
		m_rdlog->WriteLogf("PPS set Voltage:%f", Voltage);
		ret = use_gpibdev(GPIBnamestr)->PPS_SET_VOLTAGE(Voltage);
	}

	if (ret == RET_SUCCESS)
		log_sfis_and_set_info_no_judge(Itemname.c_str(), CSfisCsv::Pass, "PASS");
	else
		log_sfis_and_set_info_no_judge(Itemname.c_str(), CSfisCsv::Fail, "FAIL");

	return ret;
}

int CDut::pps_set_curr(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	string Itemname = PARAM_S("Item_Name");
	string GPIBname = PARAM_S("GPIB_Name");
	double Current = PARAM_N("Current");

	const char* GPIBnamestr = GPIBname.c_str();

	if (use_gpibdev(GPIBnamestr) != NULL)
	{
		m_rdlog->WriteLogf("PPS set Current:%f", Current);
		ret = use_gpibdev(GPIBnamestr)->PPS_SET_CURRENT(Current);
	}

	if (ret == RET_SUCCESS)
		log_sfis_and_set_info_no_judge(Itemname.c_str(), CSfisCsv::Pass, "PASS");
	else
		log_sfis_and_set_info_no_judge(Itemname.c_str(), CSfisCsv::Fail, "FAIL");

	return ret;
}

int CDut::pps_meas_curr(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	string Itemname = PARAM_S("Item_Name");
	string GPIBname = PARAM_S("GPIB_Name");
	double Meas_Curr = 0;
	double pdACCurr = 0;

	const char* Itemnamestr = Itemname.c_str();
	const char* GPIBnamestr = GPIBname.c_str();

	if (use_gpibdev(GPIBnamestr) != NULL)
	{
		m_rdlog->WriteLogf("PPS Meas Current");
		ret = use_gpibdev(GPIBnamestr)->PPS_GET_CURRENT(&pdACCurr);
	}

	Meas_Curr = pdACCurr;
	log_sfis_and_set_info(Itemnamestr, Meas_Curr);

	return ret;
}


//Isaac 34970A
int CDut::route_open(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	string Itemname = PARAM_S("Item_Name");
	string GPIBname = PARAM_S("GPIB_Name");
	int Channel = PARAM_N("Channel");

	const char* GPIBnamestr = GPIBname.c_str();

	if (use_gpibdev(GPIBnamestr) != NULL)
	{
		m_rdlog->WriteLogf("Route Open:%d", Channel);
		ret = use_gpibdev(GPIBnamestr)->ROUTE_OPEN(Channel);
	}

	if (ret == RET_SUCCESS)
		log_sfis_and_set_info_no_judge(Itemname.c_str(), CSfisCsv::Pass, "PASS");
	else
		log_sfis_and_set_info_no_judge(Itemname.c_str(), CSfisCsv::Fail, "FAIL");

	return ret;
}

int CDut::route_close(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	string Itemname = PARAM_S("Item_Name");
	string GPIBname = PARAM_S("GPIB_Name");
	int Channel = PARAM_N("Channel");

	const char* GPIBnamestr = GPIBname.c_str();

	if (use_gpibdev(GPIBnamestr) != NULL)
	{
		m_rdlog->WriteLogf("Route Close:%d", Channel);
		ret = use_gpibdev(GPIBnamestr)->ROUTE_CLOSE(Channel);
	}

	if (ret == RET_SUCCESS)
		log_sfis_and_set_info_no_judge(Itemname.c_str(), CSfisCsv::Pass, "PASS");
	else
		log_sfis_and_set_info_no_judge(Itemname.c_str(), CSfisCsv::Fail, "FAIL");

	return ret;
}

int CDut::meas_vol(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	string Itemname = PARAM_S("Item_Name");//for criteria.csv
	string GPIBname = PARAM_S("GPIB_Name");//for config.ini
	int Channel = PARAM_N("Channel");
	double pdDCVolt = 0;
	FLOAT fIntervalTime = 0;
	INT iFetchCount = 0;
	double DCVolt = 0;

	const char* GPIBnamestr = GPIBname.c_str();
	const char* Itemnamestr = Itemname.c_str();

	m_rdlog->WriteLogf("SET DMM MEAS PARA\n");

	if (use_gpibdev(GPIBnamestr) != NULL)
	{
		ret = use_gpibdev(GPIBnamestr)->SET_DMM_MEAS_PARA(DMM_TYPE_DC_VOLT, "AUTO", "6", "1", "NONE", "NONE", "OFF", -999, 1);

		if (ret == ERROR_SUCCESS) {
			m_rdlog->WriteLogf("Measure Voltage Channel:%d", Channel);
			ret = use_gpibdev(GPIBnamestr)->READ_DC_VOLTAGE(Channel, &pdDCVolt);
		}
	}

	log_sfis_and_set_info(Itemnamestr, pdDCVolt);

	return ret;
}

int CDut::meas_curr(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	string Itemname = PARAM_S("Item_Name");
	string GPIBname = PARAM_S("GPIB_Name");
	int Channel = PARAM_N("Channel");
	double pdACCurr = 0;
	FLOAT fIntervalTime = 0;
	INT iFetchCount = 0;
	double ACCurr = 0;

	const char* GPIBnamestr = GPIBname.c_str();
	const char* Itemnamestr = Itemname.c_str();

	if (use_gpibdev(GPIBnamestr) != NULL)
	{
		ret = use_gpibdev(GPIBnamestr)->SET_DMM_MEAS_PARA(DMM_TYPE_DC_CURR, "AUTO", "6", "1", "NONE", "NONE", "OFF", -999, 1);
		if (ret == ERROR_SUCCESS) {
			m_rdlog->WriteLogf("Measure Current Channel:%d", Channel);
			ret = use_gpibdev(GPIBnamestr)->READ_DC_CURRENT(Channel, &pdACCurr);
		}
	}

	log_sfis_and_set_info(Itemnamestr, pdACCurr);

	return ret;
}

int CDut::cmd_checkpoint_Log(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	m_var["CheckPoint_Log"] = true;

	ret = ERROR_SUCCESS;
	return ret;
}

int CDut::cmd_assembly_Log(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	m_var["Assembly_Log"] = true;

	ret = ERROR_SUCCESS;
	return ret;
}

int CDut::cmd_components_log(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	m_var["Components_Log"] = true;

	ret = ERROR_SUCCESS;
	return ret;
}

char* CDut::utf8_to_ansi(const char* cptr_utf8)
{
	// ref: http://www.cppblog.com/greatws/archive/2008/08/31/60546.html

	// -- UTF8 to Unicode --
	// get space that need
	int wcsLen = MultiByteToWideChar(CP_UTF8, NULL, cptr_utf8, strlen(cptr_utf8), NULL, 0);
	wchar_t* wszString = new wchar_t[wcsLen + 1];
	// convert
	MultiByteToWideChar(CP_UTF8, NULL, cptr_utf8, strlen(cptr_utf8), wszString, wcsLen);
	wszString[wcsLen] = '\0';

	//::MessageBoxW(g_uiwnd, wszString, 0, 0);

	// -- Unicode to ANSI --
	// get space that need
	int ansiLen = WideCharToMultiByte(CP_ACP, NULL, wszString, wcslen(wszString), NULL, 0, NULL, NULL);
	char* szAnsi = new char[ansiLen + 1];
	// convert
	WideCharToMultiByte(CP_ACP, NULL, wszString, wcslen(wszString), szAnsi, ansiLen, NULL, NULL);
	szAnsi[ansiLen] = '\0';

	//::MessageBoxA(g_uiwnd, szAnsi, 0, 0);
	////
	return szAnsi;
}

int CDut::cmd_message_pic_demo(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	bool pass_or_fail = PARAM_B("pass_or_fail");
	int button_num = param.isMember("button_num") ? PARAM_N("button_num") : 3;
	string pic_file = PARAM_S("pic_src");
	string description = PARAM_S("description");
	string s = pic_file + " " + description;

	// show message box with picture
	int form_ret = popup_pic_msg_form(pic_file.c_str(), description.c_str(), button_num);
	char form_ret_str[64];
	sprintf_s(form_ret_str, "form ret '%d'", form_ret);

	if (form_ret == UI_RET_YES) {
		ret = ERROR_SUCCESS;
		set_info(item, CSfisCsv::Pass, form_ret_str);
	}
	else {
		set_info(item, CSfisCsv::Fail, form_ret_str);
	}

	return ret;
}


// return value follows enum DialogResult from System.Windows.Forms.DialogResult.cs
// None = 0, OK = 1, Cancel = 2, Abort = 3, Retry = 4, Ignore = 5, Yes = 6, No = 7,
// for NOW, this form could return only Yes(6)/No(7)/Retry(4)/Cancel(2)
int CDut::popup_pic_msg_form(const char* pic, const char* desc, const int btn_num)
{
	int ret = -1;
	HANDLE event;

	g_popup_input_cs.Enter();

	event = CreateEvent(NULL, TRUE, FALSE, NULL);
	ResetEvent(event);

	m_ui->PopupPicMsgForm(event, pic, desc, btn_num);
	WaitForSingleObject(event, INFINITE);
	CloseHandle(event);

	string data1 = g_data1; // None, OK, Cancel, Abort, Retry, Ignore, Yes, No
	//string data2 = g_data2; // 
	//string data3 = g_data3;
	//::MessageBoxA(g_uiwnd, data1.c_str(), 0, 0);
	if (g_data1.compare("None") == 0) {
		ret = 0;
	}
	else if (g_data1.compare("OK") == 0) {
		ret = 1;
	}
	else if (g_data1.compare("Cancel") == 0) {
		ret = 2;
	}
	else if (g_data1.compare("Abort") == 0) {
		ret = 3;
	}
	else if (g_data1.compare("Retry") == 0) {
		ret = 4;
	}
	else if (g_data1.compare("Ignore") == 0) {
		ret = 5;
	}
	else if (g_data1.compare("Yes") == 0) {
		ret = 6;
	}
	else if (g_data1.compare("No") == 0) {
		ret = 7;
	}
	else {
		ret = -1;
	}

	g_popup_input_cs.Leave();

	return ret;
}


int CDut::cmd_write_isn(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	string item_name = param["item_name"].asString();
	string adb_cmd = param["dut_cmd"].asString();
	string reg_rule = param["reg_rule"].asString();
	//string init_cmd = "shell /home/flex/bin/fct.sh FCT.11.8";
	int reg_catch = -1;
	bool reg_enable = false;
	string adb_result;
	std::tr1::regex	rx;
	smatch reg_result;
	string value = "FAIL";
	bool stop_when_fail = false;

	if (param.isMember("stop_when_fail")) {
		if (m_sfiscsv->GetFailCount() != 0) {
			stop_when_fail = true;
		}
	}

	if (stop_when_fail == false) {

		//rx.assign("Uint", regex_constants::icase);
		//if (regex_search(m_isn, reg_result, rx) == true)
		//{
		//init_factory_partition
		/*m_rdlog->WriteLogf(" init_cmd:%s\n", adb_cmd.c_str());
		ret = adb_command(init_cmd.c_str(), adb_result);
		m_rdlog->WriteLogf(" init_result:%s<:)\n", adb_result.c_str());*/

		//if (ret == RET_SUCCESS)
		//{
		adb_cmd = adb_cmd + " " + m_isn;
		m_rdlog->WriteLogf(" adb_cmd:%s\n", adb_cmd.c_str());
		ret = adb_command(adb_cmd.c_str(), adb_result);
		m_rdlog->WriteLogf(" adb_result:%s<:)\n", adb_result.c_str());

		if (ret == RET_SUCCESS)
		{
			try
			{
				rx.assign(reg_rule, regex_constants::icase);
				if (regex_search(adb_result, reg_result, rx) == true)
				{
					for (unsigned int n = 0; n < reg_result.size(); n++)
						output_debug("reg_result[%d]:%s", n, reg_result[n].str().c_str());

					if ((reg_catch >= 0) && (reg_catch < (int)reg_result.size()))
						value = reg_result[reg_catch].str();
					else
						value = "PASS";
				}
				else
				{
					ret = RET_FAIL;
				}
			}
			catch (std::regex_error& e)
			{
				ret = RET_FAIL;
				value = "FAIL";
				m_rdlog->WriteLogf(" regex_error caught:%s\n", e.what());
			}
		}
		//}
		//else{
		//	value = "FAIL";
		//}
		//}
		//else{
		//	value = "FAIL";
		//}
	}
	else {
		ret = RET_FAIL;
		value = "FAIL";
		m_rdlog->WriteLogf("Have error before write ISN");
	}

	log_sfis_and_set_info(item_name.c_str(), value.c_str());

	return ret;
}

int CDut::cmd_read_isn(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	string item_name = param["item_name"].asString();
	string data_name = param["data_name"].asString();
	string adb_cmd = param["dut_cmd"].asString();
	string reg_rule = "PASS";
	int reg_catch = -1;
	bool reg_enable = false;
	string adb_result;
	std::tr1::regex	rx;
	smatch reg_result;
	string value = "FAIL";
	string read_isn = "";
	string token = "";
	char delim[] = "\r\n";
	vector<string> getver;
	bool into_m_isn = false;

	m_rdlog->WriteLogf(" adb_cmd:%s\n", adb_cmd.c_str());
	ret = adb_command(adb_cmd.c_str(), adb_result);
	m_rdlog->WriteLogf(" adb_result:%s<:)\n", adb_result.c_str());

	StringToken(adb_result.c_str(), getver, delim);
	read_isn = getver[0];

	m_rdlog->WriteLogf(" read_isn:%s<:)\n", read_isn.c_str());

	if (ret == RET_SUCCESS)
	{
		try
		{
			/*compare FCT_read_isn & ui_input_isn
			//if (read_isn == m_isn)
			if (read_isn != "")
			{
				value = read_isn;
				m_var[data_name] = value;
				ret = RET_SUCCESS;
			}*/
			if (read_isn.find("No such file") != -1)
			{
				value = read_isn;
				ret = RET_FAIL;
			}
			else if (read_isn != "")
			{
				value = read_isn;
				m_var[data_name] = value;
				ret = RET_SUCCESS;
				into_m_isn = param.isMember("m_isn");
				if (into_m_isn == true) {
					m_isn = value;
					if (!m_isn.empty())
					{
						m_ui->UpdateIsn(m_isn.c_str());
						m_rdlog->Rename(m_isn.c_str());
						m_sfiscsv->Rename(m_isn.c_str());
						m_gpiblog->Rename(m_isn.c_str());
					}
				}
			}
			else
			{
				value = "FAIL";
				ret = RET_FAIL;
			}
		}
		catch (std::regex_error& e)
		{
			ret = RET_FAIL;
			value = "FAIL";
			m_rdlog->WriteLogf(" regex_error caught:%s\n", e.what());
		}
	}

	log_sfis_and_set_info_no_judge(item_name.c_str(), (ret == RET_SUCCESS ? CSfisCsv::Pass : CSfisCsv::Fail), value.c_str());

	return ret;
}

int CDut::cmd_adb_command_mb(const char* item, const Json::Value& param) {
	int ret = RET_FAIL;
	string item_name = param["item_name"].asString();
	string pic_file = PARAM_S("pic_src");
	string description = PARAM_S("description");
	bool is_utf8 = param["is_utf8"].asBool();
	string adb_cmd = param["dut_cmd"].asString();
	int sleep_time = PARAM_N("delay");
	int button_num = param.isMember("button_num") ? PARAM_N("button_num") : 2;
	string adb_result;
	string value = "FAIL";
	bool all_pass_exit = false;
	bool cmd_after_click = false;
	int retrytimes = 1;
	int count = 0;
	bool reg_enable = false;
	string reg_rule;
	std::tr1::regex	rx;
	int reg_catch = -1;
	smatch reg_result;

	//execute cmd after click button
	if (param.isMember("cmd_after_click"))
	{
		cmd_after_click = param["cmd_after_click"].asBool();
	}
	if (cmd_after_click == false) {
		ret = adb_command(adb_cmd.c_str(), adb_result);
		m_rdlog->WriteLogf(" result of adb device:%s\n", adb_result.c_str());
	}

	Sleep(sleep_time);

	if (param.isMember("all_pass_exit"))
	{
		all_pass_exit = param["all_pass_exit"].asBool();
	}
	if (param.isMember("retrytimes"))
	{
		retrytimes = PARAM_N("retrytimes");
	}

	for (count; count < retrytimes; count++) {

		//show message box with picture
		int form_ret = -1;
		if (is_utf8 == true) {
			m_rdlog->WriteLogf(" use description as UTF8\n");
			char* desc_ansi = utf8_to_ansi(description.c_str());
			form_ret = popup_pic_msg_form(pic_file.c_str(), desc_ansi, button_num);
			delete[] desc_ansi;
		}
		else {
			m_rdlog->WriteLogf(" use description as ANSI\n");
			form_ret = popup_pic_msg_form(pic_file.c_str(), description.c_str(), button_num);
		}

		//int form_ret = popup_pic_msg_form(pic_file.c_str(), description.c_str(), button_num);
		char form_ret_str[64];
		sprintf_s(form_ret_str, "form ret '%d'", form_ret);


		if (form_ret == UI_RET_YES) {

			//start find string
			ret = ERROR_SUCCESS;
			if (cmd_after_click == true) {
				ret = adb_command(adb_cmd.c_str(), adb_result);
				m_rdlog->WriteLogf(" result of adb device:%s\n", adb_result.c_str());
				if (ret == RET_SUCCESS)
				{
					if (param.isMember("reg_enable"))
					{
						reg_enable = param["reg_enable"].asBool();
						reg_rule = param["reg_rule"].asString();
						if (param.isMember("reg_catch"))
							reg_catch = param["reg_catch"].asInt();
					}

					if (reg_enable == true)
					{
						try
						{
							rx.assign(reg_rule, regex_constants::icase);
							if (regex_search(adb_result, reg_result, rx) == true)
							{
								for (unsigned int n = 0; n < reg_result.size(); n++)
									output_debug("reg_result[%d]:%s", n, reg_result[n].str().c_str());

								if ((reg_catch >= 0) && (reg_catch < (int)reg_result.size()))
									value = reg_result[reg_catch].str();
								else
									value = "PASS";
							}
							else
							{
								ret = RET_FAIL;
							}
						}
						catch (std::regex_error& e)
						{
							ret = RET_FAIL;
							value = "FAIL";
							m_rdlog->WriteLogf(" regex_error caught:%s\n", e.what());
						}
					}
					else
						value = "PASS";
				}
			}
			else {
				value = "PASS";
			}
		}
		else if (form_ret == UI_RET_NO) {
			value = "FAIL";
		}

		if (ret == RET_SUCCESS && all_pass_exit == true) {
			break;
		}
	}

	log_sfis_and_set_info(item_name.c_str(), value.c_str());

	return ret;
}

int CDut::cmd_adb_command_ex(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	string item_name = param["item_name"].asString();
	string reg_rule;
	int reg_catch = -1;
	bool reg_enable = false;
	string adb_cmd = param["dut_cmd"].asString();
	string adb_result;
	std::tr1::regex	rx;
	smatch reg_result;
	string value = "FAIL";
	string tmnl = param["tmnl"].asString();
	int wait = PARAM_N("wait");
	int timeout = PARAM_N("timeout");

	m_rdlog->WriteLogf(" adb_cmd:%s\n", adb_cmd.c_str());
	ret = adb_command(adb_cmd.c_str(), adb_result, tmnl.c_str(), wait, timeout);
	m_rdlog->WriteLogf(" adb_result:%s<:)\n", adb_result.c_str());

	if (ret == RET_SUCCESS)
	{
		if (param.isMember("reg_enable"))
		{
			reg_enable = param["reg_enable"].asBool();
			reg_rule = param["reg_rule"].asString();
			if (param.isMember("reg_catch"))
				reg_catch = param["reg_catch"].asInt();
		}

		if (reg_enable == true)
		{
			try
			{
				rx.assign(reg_rule, regex_constants::icase);
				if (regex_search(adb_result, reg_result, rx) == true)
				{
					for (unsigned int n = 0; n < reg_result.size(); n++)
						output_debug("reg_result[%d]:%s", n, reg_result[n].str().c_str());

					if ((reg_catch >= 0) && (reg_catch < (int)reg_result.size()))
						value = reg_result[reg_catch].str();
					else
						value = "PASS";
				}
				else
				{
					ret = RET_FAIL;
				}
			}
			catch (std::regex_error& e)
			{
				ret = RET_FAIL;
				value = "FAIL";
				m_rdlog->WriteLogf(" regex_error caught:%s\n", e.what());
			}
		}
		else
			value = "PASS";
	}

	log_sfis_and_set_info(item_name.c_str(), value.c_str());

	return ret;
}

// add by Brighd -- start	20180130
int CDut::cmd_when(const char* item, const Json::Value& param)
{
	int ret = RET_FAIL;
	int itemsize = 0;
	bool docase = false;
	string item_name;
	Json::Value item_param;

	string condition_key = param["condition_key"].asString();
	string condition_value = m_var[condition_key].asString();
	Json::Value test_items = param[condition_value];

	itemsize = test_items.size();
	if (itemsize != 0)
	{
		for (int i = 0; i < itemsize; i++)
		{
			item_name = test_items[i].getMemberNames()[0];
			if (item_name == "else")
				continue;
			if (item_name[0] != '#')
			{
				item_param = test_items[i][item_name];
				int ret = run_script_command(item_name, item_param);
				docase = true;
			}
		}
	}
	if (docase == false)
	{
		test_items = param["else"];
		itemsize = test_items.size();
		if (itemsize != 0)
		{
			for (int i = 0; i < itemsize; i++)
			{
				item_name = test_items[i].getMemberNames()[0];
				if (item_name[0] != '#')
				{
					item_param = test_items[i][item_name];
					int ret = run_script_command(item_name, item_param);
				}
			}
		}
	}
	return ret;
}

// add by Brighd -- end		20180202

int CDut::cmd_get_fatp_isn_via_ssn(const char* item, const Json::Value& param) {
	int ret = RET_FAIL;
	string chk_type;
	string chk_data1, chk_data2;
	vector<string> getver;
	unsigned int idx;
	string catch_value;
	string unknown_isn;

	unknown_isn = m_input_data[0];
	chk_type = "ITEMINFO";
	chk_data1 = "ISN";
	chk_data2 = "";
	idx = 4;
	catch_value = "";

	m_rdlog->WriteLogf(" input isn: '%s'\n", unknown_isn.c_str());
	if (strlen(m_input_data[0]) != 0) {
		ret = sfis_get_version(unknown_isn.c_str(), chk_type.c_str(), chk_data1.c_str(), chk_data2.c_str(), getver);
		for (unsigned int i = 0; i < getver.size(); i++) {
			m_rdlog->WriteLogf(" getver[%d]: '%s'\n", i, getver[i].c_str());
		}

		if (ret == RET_SUCCESS)
		{
			if (idx < getver.size()) {
				catch_value = getver[idx];
				if (strlen(catch_value.c_str()) != 0) {
					//m_input_data[0] = catch_value.c_str();
					m_rdlog->WriteLogf(" get fatp isn: '%s'\n", catch_value.c_str());
					sprintf_s(m_input_data[0], "%s", catch_value.c_str());
				}
				else {
					m_rdlog->WriteLogf(" strlen(catch_value.c_str()) != 0 fail\n");
					ret = RET_FAIL;
					m_exit_test_and_no_sfis = true;
				}
			}
			else {
				m_rdlog->WriteLogf(" idx < getver.size() fail\n");
				ret = RET_FAIL;
				m_exit_test_and_no_sfis = true;
			}
		}
		else {
			m_rdlog->WriteLogf(" ret == RET_SUCCESS fail\n");
			ret = RET_FAIL;
			m_exit_test_and_no_sfis = true;
		}
	}

	m_rdlog->WriteLogf(" rewrite m_input_data[0]: '%s'\n", m_input_data[0]);

	log_sfis_and_set_info_no_judge(item,
		(ret == RET_SUCCESS ? CSfisCsv::Pass : CSfisCsv::Fail),
		m_input_data[0]);
	return ret;
}

string CDut::sfis_get_device_config() {
	int ret = RET_FAIL;
	string chk_type;
	string chk_data1, chk_data2;
	vector<string> getver;
	unsigned int idx;
	string catch_value;
	string isn;
	string device_config;

	isn = m_input_data[0];
	chk_type = "GET_CONFIG";
	chk_data1 = "MO_MEMO";
	chk_data2 = "";
	idx = 2;
	catch_value = "";

	m_rdlog->WriteLogf(" input isn: '%s'\n", isn.c_str());
	if (strlen(m_input_data[0]) != 0) {
		ret = sfis_get_version(isn.c_str(), chk_type.c_str(), chk_data1.c_str(), chk_data2.c_str(), getver);
		for (unsigned int i = 0; i < getver.size(); i++) {
			m_rdlog->WriteLogf(" getver[%d]: '%s'\n", i, getver[i].c_str());
		}

		if (ret == RET_SUCCESS)
		{
			if (idx < getver.size()) {
				catch_value = getver[idx];
				if (strlen(catch_value.c_str()) != 0) {
					m_rdlog->WriteLogf(" get DEVICE_CONFIG: '%s'\n", catch_value.c_str());
				}
				else {
					m_rdlog->WriteLogf(" strlen(catch_value.c_str()) != 0 fail\n");
					ret = RET_FAIL;
				}
			}
			else {
				m_rdlog->WriteLogf(" idx < getver.size() fail\n");
				ret = RET_FAIL;
			}
		}
		else {
			m_rdlog->WriteLogf(" ret == RET_SUCCESS fail\n");
			ret = RET_FAIL;
		}
	}

	return catch_value;
}



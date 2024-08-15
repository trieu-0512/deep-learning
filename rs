#include "stdafx.h"
//***************************************************************************
// Describtion：RS232 SERIAL COM PORT COMMUNICATION
//***************************************************************************
#include "RS232.h"


//***************************************************************************
// Describtion：CONSTRUCTOR/DESTRUCTOR
//***************************************************************************

CRS232::CRS232() :m_baudrate(115200), m_is_open(false)
{
	::OutputDebugStringA("CRS232::CRS232()\n");
	m_hCOM = NULL;

	m_cfg.bEnable = TRUE;
	m_cfg.iCOM = -1;
	m_cfg.BaudRate = this->m_baudrate;
	m_cfg.ByteSize = 8;
	m_cfg.FlowControl = FLOW_CONTROL_OFF;
	m_cfg.Parity = 0;
	m_cfg.StopBits = 0;
	m_cfg.fBinary = 1;
}

CRS232::CRS232(std::string comport) :m_baudrate(115200), m_enable_set_state(TRUE), m_is_open(false)
{
	::OutputDebugStringA("CRS232::CRS232()\n");
	m_hCOM = NULL;

	strcpy_s(m_com_name, comport.c_str());

	std::string port = comport.substr(3, 3);
	m_cfg.iCOM = atoi(port.c_str());

	m_cfg.bEnable = TRUE;
	m_cfg.BaudRate = this->m_baudrate;
	m_cfg.ByteSize = 8;
	m_cfg.FlowControl = FLOW_CONTROL_OFF;
	m_cfg.Parity = 0;
	m_cfg.StopBits = 0;
	m_cfg.fBinary = 1;
}

CRS232::CRS232(RS232_CONFIG& cfg) :m_enable_set_state(TRUE), m_is_open(false)
{
	memcpy_s(&m_cfg, sizeof(cfg), &cfg, sizeof(cfg));
	sprintf_s(m_com_name, "COM%d", m_cfg.iCOM);
}

CRS232::~CRS232() 
{
	::OutputDebugStringA("CRS232::~CRS232()\n");
	if(NULL != m_hCOM)
	{
		::CloseHandle(m_hCOM);
		m_hCOM = NULL;
	}
}

INT CRS232::Open()
{	
	if (m_cfg.iCOM == -1)
	{
		::MessageBoxA(NULL, "not specify com port yet!", "COM PORT", MB_OK);
		return RS232_OPEN_FAIL;
	}

	return Open(m_cfg, this->m_enable_set_state);
}

INT CRS232::Open(std::string comport, DWORD baudrate, BOOL EnableSetState)
{
	std::string port = comport.substr(3, 3);
	m_cfg.iCOM = atoi(port.c_str());

	this->m_baudrate = baudrate;
	this->m_enable_set_state = EnableSetState;
	return Open();
}

//***************************************************************************
// Describtion：RS232 OPEN COM PORT
//***************************************************************************
INT CRS232::Open(RS232_CONFIG stConfig, BOOL EnableSetState)
{
	DCB             stDCB;
	COMMTIMEOUTS    stTimeout;
	CHAR            szFileName[16] = {0x00};
	DWORD			last_error = 0;
	char*			error_message;

	// Set Port String and Number
	sprintf_s(m_com_name, "COM%d", stConfig.iCOM);
	sprintf_s(szFileName, "\\\\.\\COM%d", stConfig.iCOM);
	m_hCOM = ::CreateFileA(	szFileName,
							GENERIC_READ | GENERIC_WRITE,
							0,					//shared
							NULL,				//security
							OPEN_EXISTING,
							FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
							NULL);

	if(INVALID_HANDLE_VALUE == m_hCOM)
	{
		last_error = ::GetLastError();
		FormatMessage ( FORMAT_MESSAGE_ALLOCATE_BUFFER  | FORMAT_MESSAGE_IGNORE_INSERTS  | FORMAT_MESSAGE_FROM_SYSTEM, NULL,
			last_error, LANG_NEUTRAL, (LPTSTR) & error_message, 0 , NULL);
		::OutputDebugStringA(error_message);
		LocalFree (error_message);
		::CloseHandle(m_hCOM);
		//m_hCOM = NULL;
		return RS232_HANDLE_FAIL;
	}

	this->m_enable_set_state = EnableSetState;
	if (m_enable_set_state == TRUE)
	{
		::GetCommState(m_hCOM, &stDCB);
		/*char			mode[128];
		sprintf_s(mode, "COM%d 9600,n,8,1", stConfig.iCOM);
		::BuildCommDCB(mode, &stDCB);*/

		// Set port parameters
		stDCB.DCBlength				= sizeof(DCB);
		stDCB.BaudRate				= stConfig.BaudRate;	//CBR_9600
		stDCB.Parity				= stConfig.Parity;		//NOPARITY
		stDCB.ByteSize				= stConfig.ByteSize;	//8
		stDCB.StopBits				= stConfig.StopBits;	//1
		stDCB.fBinary				= stConfig.fBinary;		//1
		stDCB.fTXContinueOnXoff		= FALSE;				//TRUE
		stDCB.StopBits				= ONESTOPBIT;

		switch(stConfig.FlowControl)
		{
		case FLOW_CONTROL_OFF:
			stDCB.fOutxCtsFlow		= FALSE;
			stDCB.fOutxDsrFlow		= FALSE;
			stDCB.fDsrSensitivity	= FALSE;
			stDCB.fDtrControl		= DTR_CONTROL_ENABLE;
			stDCB.fRtsControl		= RTS_CONTROL_ENABLE;
			stDCB.fOutX				= FALSE;
			stDCB.fInX				= FALSE;
			break;
		case FLOW_CONTROL_SOFTWARE:
			stDCB.fOutxCtsFlow		= FALSE;
			stDCB.fOutxDsrFlow		= FALSE;
			stDCB.fDsrSensitivity	= FALSE;
			stDCB.fDtrControl		= DTR_CONTROL_ENABLE;
			stDCB.fRtsControl		= RTS_CONTROL_ENABLE;
			stDCB.fOutX				= TRUE;
			stDCB.fInX				= TRUE;
			break;
		case FLOW_CONTROL_HARDWARE:
			stDCB.fOutxCtsFlow		= TRUE;
			stDCB.fOutxDsrFlow		= TRUE;
			stDCB.fDsrSensitivity	= TRUE;
			stDCB.fDtrControl		= DTR_CONTROL_ENABLE;
			stDCB.fRtsControl		= RTS_CONTROL_HANDSHAKE;
			stDCB.fOutX				= FALSE;
			stDCB.fInX				= FALSE;
			break;
		default:
			break;
		}

		if(FALSE == ::SetCommState(m_hCOM, &stDCB))
		{
			::OutputDebugStringA("failed to SetCommState()");
			Sleep(50);
			if(FALSE == ::SetCommState(m_hCOM, &stDCB))
			{
				last_error = ::GetLastError();
				FormatMessage ( FORMAT_MESSAGE_ALLOCATE_BUFFER  | FORMAT_MESSAGE_IGNORE_INSERTS  | FORMAT_MESSAGE_FROM_SYSTEM, NULL,
					last_error, LANG_NEUTRAL, (LPTSTR) & error_message, 0 , NULL);
				::OutputDebugStringA(error_message);
				LocalFree (error_message);
				::CloseHandle(m_hCOM);
				//m_hCOM = NULL;
				return last_error/*RS232_OPEN_FAIL*/;
			}
		}
	}


	if(!SetCommMask(m_hCOM, EV_RXCHAR))
	{
		::OutputDebugStringA("failed to SetCommMask()");
		Sleep(50);
		if(!SetCommMask(m_hCOM, EV_RXCHAR))
		{
			last_error = ::GetLastError();
			FormatMessage ( FORMAT_MESSAGE_ALLOCATE_BUFFER  | FORMAT_MESSAGE_IGNORE_INSERTS  | FORMAT_MESSAGE_FROM_SYSTEM, NULL,
				last_error, LANG_NEUTRAL, (LPTSTR) & error_message, 0 , NULL);
			::OutputDebugStringA(error_message);
			LocalFree (error_message);
			Close();
			return RS232_OPEN_FAIL;
		}
	}
	// Set Buffer Size
	if(!::SetupComm(m_hCOM, 4096, 4096))
	{
		::OutputDebugStringA("failed to SetupComm()");
		Sleep(50);
		if(!::SetupComm(m_hCOM, 4096, 4096))
		{
			last_error = ::GetLastError();
			FormatMessage ( FORMAT_MESSAGE_ALLOCATE_BUFFER  | FORMAT_MESSAGE_IGNORE_INSERTS  | FORMAT_MESSAGE_FROM_SYSTEM, NULL,
				last_error, LANG_NEUTRAL, (LPTSTR) & error_message, 0 , NULL);
			::OutputDebugStringA(error_message);
			LocalFree (error_message);
			Close();
			return RS232_OPEN_FAIL;
		}
	}

	::PurgeComm(m_hCOM, PURGE_TXABORT|PURGE_RXABORT|PURGE_TXCLEAR|PURGE_RXCLEAR);

	::ZeroMemory(&m_OverlappedRead, sizeof(OVERLAPPED));
	::ZeroMemory(&m_OverlappedWrite, sizeof(OVERLAPPED));
	m_OverlappedRead.hEvent = ::CreateEvent(NULL, TRUE, FALSE, NULL);
	m_OverlappedWrite.hEvent = ::CreateEvent(NULL, TRUE, FALSE, NULL);

	// Set no time for port
	stTimeout.ReadIntervalTimeout           = MAXDWORD;
	stTimeout.ReadTotalTimeoutConstant      = 0;
	stTimeout.ReadTotalTimeoutMultiplier    = 0;
	stTimeout.WriteTotalTimeoutConstant     = 5000;
	stTimeout.WriteTotalTimeoutMultiplier   = 10;
	if(!::SetCommTimeouts(m_hCOM, &stTimeout))
	{
		last_error = ::GetLastError();
		FormatMessage ( FORMAT_MESSAGE_ALLOCATE_BUFFER  | FORMAT_MESSAGE_IGNORE_INSERTS  | FORMAT_MESSAGE_FROM_SYSTEM, NULL,
			last_error, LANG_NEUTRAL, (LPTSTR) & error_message, 0 , NULL);
		::OutputDebugStringA(error_message);
		LocalFree (error_message);
		Close();
		return RS232_OPEN_FAIL;
	}

	this->m_is_open = true;

	return ERROR_SUCCESS;
}
//***************************************************************************
// Describtion：RS232 CLOSE COM PORT
//***************************************************************************

INT CRS232::Close(VOID)
{
	if ((INVALID_HANDLE_VALUE != m_hCOM) || (NULL != m_hCOM))
	{
		//::EscapeCommFunction(m_hCOM, CLRDTR);
		//::EscapeCommFunction(m_hCOM, CLRRTS);
		::SetCommMask(m_hCOM, 0);
		::PurgeComm(m_hCOM, PURGE_TXABORT|PURGE_RXABORT|PURGE_TXCLEAR|PURGE_RXCLEAR);
		::CloseHandle(m_hCOM);
		m_hCOM = NULL;
	}

	this->m_is_open = false;

	return ERROR_SUCCESS;
}
//***************************************************************************
// Describtion：RS232 DETECT COM PORT
//***************************************************************************

INT CRS232::Detect(CONST INT iID)
{
	HANDLE	hCOM = NULL;
	CHAR	szFileName[16] = {0x00};
	sprintf_s(szFileName, "\\\\.\\COM%d", iID);
	hCOM = ::CreateFileA(	szFileName,
							GENERIC_READ | GENERIC_WRITE,
							0,					//not shared
							NULL,				//no security
							OPEN_EXISTING,
							FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
							NULL				//template
	);

	if(INVALID_HANDLE_VALUE == hCOM) 
	{
		::CloseHandle(hCOM);
		return RS232_HANDLE_FAIL;
	}

	// Detected COM then Close Handle
	::CloseHandle(hCOM);
	return ERROR_SUCCESS;
}
//***************************************************************************
// Describtion：RS232 WRITE STRING
//***************************************************************************

INT CRS232::WriteString(CONST CHAR *pcCommand, bool do_clear)
{
	DWORD dwBytesWrite = 0;
	if (do_clear) Clear();
	if(FALSE == ::WriteFile(m_hCOM, pcCommand, (INT)strlen(pcCommand), &dwBytesWrite, &m_OverlappedWrite))
	{
		if(ERROR_IO_PENDING == ::GetLastError())
		{
			//::OutputDebugStringA("===================> WriteString:ERROR_IO_PENDING\n");
			if(::WaitForSingleObject(m_OverlappedWrite.hEvent, 1000))
			{
				::OutputDebugStringA("TRUE\n");
				dwBytesWrite = -1;
				return -1;
			}
			else
			{
				//::OutputDebugStringA("FALSE\n");
				::GetOverlappedResult(m_hCOM, &m_OverlappedWrite, &dwBytesWrite, FALSE);
			}
		}
		else
		{
		}
	}
	return ERROR_SUCCESS;
}
//***************************************************************************
// Describtion：RS232 READ STRING
//***************************************************************************

INT CRS232::ReadString(CHAR *pcBuffer, DWORD size)
{
	INT			iStatus = ERROR_SUCCESS;
	DWORD 		dwBytesRead = 0;
	DWORD 		dwCommError = 0;
	CHAR 		szInBuffer[40960] = {0x00};
	COMSTAT 	CS;

	::ClearCommError(m_hCOM, &dwCommError, &CS);

	if(0 == CS.cbInQue)
		iStatus = RS232_READ_FAIL+100;

	if (iStatus == ERROR_SUCCESS)
	{
		if(CS.cbInQue > sizeof(szInBuffer))
		{
			::PurgeComm(m_hCOM, PURGE_RXCLEAR);
			iStatus = RS232_READ_FAIL+101;
		}
	}

	if (iStatus == ERROR_SUCCESS)
	{
		dwBytesRead = (DWORD)CS.cbInQue;

		if(FALSE == ::ReadFile(m_hCOM, szInBuffer, CS.cbInQue, &dwBytesRead, &m_OverlappedRead))
		{
			if(ERROR_IO_PENDING == ::GetLastError())
			{
				::OutputDebugStringA("===================> ReadString:ERROR_IO_PENDING\n");
				if(::WaitForSingleObject(m_OverlappedRead.hEvent, 1000))
				{					
					::OutputDebugStringA("TRUE\n");
					dwBytesRead = -1;
				}
				else
				{
					::OutputDebugStringA("FALSE\n");
					::GetOverlappedResult(m_hCOM, &m_OverlappedRead, &dwBytesRead, FALSE);
					szInBuffer[dwBytesRead] = '\0';
					strcpy_s(pcBuffer, size, szInBuffer);
				}
			}
			iStatus = RS232_READ_FAIL+102;
		}
		else
		{
			if(0 < dwBytesRead)
			{
				pcBuffer[dwBytesRead] = '\0';
				strcpy_s(pcBuffer, size, szInBuffer);
			}
		}
	}

	return iStatus;
}

//***************************************************************************
// Describtion：RS232 READ STRING, return by CString
//***************************************************************************

INT CRS232::ReadString(string& read_data)
{
	int		ret = ERROR_SUCCESS;
	char	buffer[4096];
	DWORD	ta;
	DWORD	tb;
	
	buffer[0] = 0x00;
	read_data.clear();
	ta = ::GetTickCount();
	while (ret == ERROR_SUCCESS)
	{
		buffer[0] = 0x00;
		ret = ReadString(buffer, _countof(buffer));
		read_data += buffer;
		if (ret != ERROR_SUCCESS)
			break;
		Sleep(50);

		tb = ::GetTickCount();
		if ((tb-ta)>800)
			break;
	}

	if ((read_data.empty() != true)  && (ret==RS232_READ_FAIL+100))
		return ERROR_SUCCESS;
	else
		return ret;
}

INT CRS232::ReadString(string& read_data, const char* tmnl, int timeout)
{
	int		ret = -1/*ERROR_SUCCESS*/;
	char	buffer[4096];
	DWORD	ta;
	DWORD	tb;
	
	buffer[0] = 0x00;
	read_data.clear();
	ta = ::GetTickCount();
	while (1/*ret == ERROR_SUCCESS*/)
	{
		buffer[0] = 0x00;
		ret = ReadString(buffer, _countof(buffer));
		read_data += buffer;
		if ((strstr(buffer, tmnl)!=NULL)/* && (ret==ERROR_SUCCESS)*/)
		{
			ret = ERROR_SUCCESS;
			break;
		}
		Sleep(10);

		tb = ::GetTickCount();
		if ((tb-ta)>(DWORD)timeout)
			break;
	}

	if ((read_data.empty() != true)  && (ret==RS232_READ_FAIL+100))
		return ERROR_SUCCESS;
	else
		return ret;
}

//***************************************************************************
// Describtion：RS232 WRITE BYTE
//***************************************************************************

INT CRS232::WriteByte(RS232_AT_COMMAND &cmd)
{
	DWORD dwWriteBytes = 0;

	if(FALSE == ::WriteFile(m_hCOM, cmd.szCommand, cmd.dwLength, &dwWriteBytes, &m_OverlappedWrite))
	{
		if(ERROR_IO_PENDING == ::GetLastError())
		{
			if(::WaitForSingleObject(m_OverlappedWrite.hEvent, INFINITE))
			{
				dwWriteBytes = -1;
			}
			else
			{
				::GetOverlappedResult(m_hCOM, &m_OverlappedWrite, &dwWriteBytes, FALSE);
			}
		}
	}
	return ERROR_SUCCESS;
}
//***************************************************************************
// Describtion：RS232 READ BYTE
//***************************************************************************

INT CRS232::ReadByte(CHAR *pcBuffer)
{
	DWORD 		dwReadBytes = 0;
	DWORD 		dwCommError = 0;
	CHAR 		szInBuffer[1024] = {0x00};
	COMSTAT 	CS;
	
	::ClearCommError(m_hCOM, &dwCommError, &CS);

	if(0 == CS.cbInQue)
	{
		return RS232_READ_FAIL;
	}
	if(CS.cbInQue > sizeof(szInBuffer))
	{
		::PurgeComm(m_hCOM, PURGE_RXCLEAR);
		return RS232_READ_FAIL;
	}

	dwReadBytes = (DWORD)CS.cbInQue;

	if(FALSE == ::ReadFile(m_hCOM, szInBuffer, CS.cbInQue, &dwReadBytes, &m_OverlappedRead))
	{
		if(ERROR_IO_PENDING == ::GetLastError())
		{
			if(::WaitForSingleObject(m_OverlappedRead.hEvent, INFINITE))
			{
				dwReadBytes = -1;
				return RS232_READ_FAIL;
			}
			else
			{
				::GetOverlappedResult(m_hCOM, &m_OverlappedRead, &dwReadBytes, FALSE);
				for(DWORD i=0; i<dwReadBytes; i++)
				{
					pcBuffer[i] = szInBuffer[i];
				}
				pcBuffer[dwReadBytes] = '\0';
			}
		}
	}
	else
	{
		for(DWORD i=0; i<dwReadBytes; i++)
		{
			pcBuffer[i] = szInBuffer[i];
		}
		pcBuffer[dwReadBytes] = '\0';

		/*CString csTemp = pcBuffer;

		csTemp.Replace("\r\n", "\n");
		csTemp.Replace("\n", "\r\n");

		strcpy(pcBuffer, csTemp.GetBuffer());
		csTemp.ReleaseBuffer();*/
	}

	return ERROR_SUCCESS;
}

INT CRS232::WRString(const char* write, string& read, int wait)
{
	int ret = ERROR_SUCCESS;
	string s;

	ret = WriteString(write);
	//if (ret == ERROR_SUCCESS)
	{
		//Sleep(wait);
		//ret = WriteString("\r", false);
		if (ret == ERROR_SUCCESS)
		{
			Sleep(wait);
			ret = ReadString(read);
		}
	}
	/*if (ret == ERROR_SUCCESS)
	{
		if (read.length() > 9)
		{
			s = read.substr(read.length() - 5, 5);
			if (read.compare(read.length() - 9, 4, s, 1, 4) == 0)
			{
				read.erase(read.length() - 5, 5);
			}
			else if (read.compare(read.length() - 6, 3, s, 2, 3) == 0)
			{
				read.erase(read.length() - 3, 3);
			}
		}*/

		/*Sleep(wait);
		ret = ReadString(read);*/
		/*if ((read.find("status = -1")!=string::npos) || (read.find("status = -2")!=string::npos))
			ret = -1;*/
	//}
	return ret;
}

INT CRS232::WRString(const char* write, string& read, const char* tmnl, int wait, int timeout)
{
	int ret = ERROR_SUCCESS;
	char wb[2] = {0};
	/*for (int n=0; n<strlen(write); n++)
	{
		wb[0] = write[n];
		ret = WriteString(wb);
		Sleep(50);
	}*/
	ret = WriteString(write);
	if (ret == ERROR_SUCCESS)
	{
		Sleep(wait);
		ret = ReadString(read, tmnl, timeout);
		/*if ((read.find("status = -1")!=string::npos) || (read.find("status = -2")!=string::npos))
			ret = -1;*/
	}
	return ret;
}

void CRS232::PurgeComm()
{
	::PurgeComm(m_hCOM, PURGE_RXCLEAR);
}

VOID CRS232::Clear(VOID)
{
	if(INVALID_HANDLE_VALUE != m_hCOM)
		::PurgeComm(m_hCOM, PURGE_TXABORT|PURGE_RXABORT|PURGE_TXCLEAR|PURGE_RXCLEAR);
}

bool CRS232::IsOpen()
{
	return this->m_is_open;
}

char* CRS232::ComName()
{
	return this->m_com_name;
}



//***************************************************************************
// Describtion：END
//***************************************************************************

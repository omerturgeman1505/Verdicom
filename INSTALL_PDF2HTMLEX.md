# התקנת pdf2htmlEX ב-Windows

## אפשרות 1: הורדת גרסה מוכנה (מומלץ - הכי קל)

### שלב 1: הורדת הגרסה
1. עבור ל: **https://github.com/pdf2htmlEX/pdf2htmlEX/releases**
2. הורד את הקובץ המתאים ל-Windows:
   - חפש קבצים כמו `pdf2htmlEX-windows.zip` או `.exe`
   - אם אין גרסת Windows, תוכל להשתמש ב-Docker (ראה אפשרות 4)

### שלב 2: התקנה
**אם הורדת `.exe` או `.zip`:**
1. פתח את הקובץ שהורד
2. חלץ את `pdf2htmlEX.exe` לתיקייה (לדוגמה: `C:\tools\pdf2htmlEX\`)
3. הוסף את התיקייה ל-PATH:
   - לחץ **Windows + R**
   - הקלד `sysdm.cpl` ולחץ Enter
   - לך לטאב **"Advanced"**
   - לחץ על **"Environment Variables"**
   - ב-"System variables", מצא `Path` ולחץ **Edit**
   - לחץ **New** והוסף את הנתיב (לדוגמה: `C:\tools\pdf2htmlEX`)
   - לחץ **OK** בכל החלונות

**או צור משתנה סביבה מותאם:**
1. ב-"User variables" או "System variables", לחץ **New**
2. Name: `PDF2HTMLEX_PATH`
3. Value: הנתיב המלא לקובץ, לדוגמה: `C:\tools\pdf2htmlEX\pdf2htmlEX.exe`
4. לחץ **OK**

### שלב 3: בדיקה
פתח **Command Prompt** או **PowerShell** והקלד:
```bash
pdf2htmlEX --version
```

אם זה עובד, ההתקנה הצליחה! 🎉

---

## אפשרות 2: התקנה דרך WSL2 (Windows Subsystem for Linux) - מומלץ!

אם יש לך WSL2 מותקן (או תוכל להתקין):

```bash
# פתח WSL
wsl

# עדכן את המאגרים
sudo apt-get update

# התקן ישירות (הכי קל)
sudo apt-get install pdf2htmlEX

# בדוק שההתקנה הצליחה
pdf2htmlEX --version
```

**יתרונות:**
- פשוט מאוד
- עובד מצוין
- עדכונים אוטומטיים

**אם אין לך WSL2:**
1. פתח PowerShell כמנהל
2. הרץ: `wsl --install`
3. הפעל מחדש את המחשב
4. חזור לשלבים למעלה

---

## אפשרות 3: בנייה מקוד המקור ב-WSL2

אם ההתקנה דרך apt לא עובדת, תוכל לבנות מקוד המקור:

```bash
# פתח WSL
wsl

# היכנס לתיקיית הפרויקט
cd /mnt/c/Users/omert/Mobileye-Threat/threat-Mobileye-dashboard/Pdf-Viewer

# התקן תלויות
sudo apt-get update
sudo apt-get install -y build-essential cmake git

# הרץ את סקריפט הבנייה
chmod +x buildScripts/buildInstallLocallyApt
./buildScripts/buildInstallLocallyApt
```

זה יקח זמן רב (10-30 דקות) אבל יתקין את הגרסה האחרונה.

---

## אפשרות 4: שימוש ב-Docker (אם יש לך Docker Desktop)

### התקנת Docker Desktop:
1. הורד מ: https://www.docker.com/products/docker-desktop
2. התקן והפעל מחדש

### שימוש:
```bash
# הרץ את זה ב-PowerShell או Command Prompt
docker pull pdf2htmlex/pdf2htmlex

# או להשתמש ישירות:
docker run --rm -v "%cd%":/data pdf2htmlex/pdf2htmlex input.pdf output.html
```

**לשימוש בתוך Python**, תצטרך לעדכן את `app.py` להשתמש ב-Docker.

---

## אפשרות 5: התקנה דרך Chocolatey (אם יש לך Chocolatey)

```powershell
# פתח PowerShell כמנהל
choco install pdf2htmlEX
```

אם אין לך Chocolatey:
1. פתח PowerShell כמנהל
2. הרץ:
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
```
3. התקן:
```powershell
choco install pdf2htmlEX
```

---

## אפשרות 6: שימוש בנתיב ישיר (ללא PATH)

אם התקנת את `pdf2htmlEX.exe` במקום מסוים, אפשר להגדיר משתנה סביבה:

```powershell
# ב-PowerShell, הפעל:
[Environment]::SetEnvironmentVariable("PDF2HTMLEX_PATH", "C:\path\to\pdf2htmlEX.exe", "User")
```

או ערוך ידנית:
1. לחץ **Windows + R**
2. הקלד `sysdm.cpl` ולחץ Enter
3. **Environment Variables** → **New**
4. Name: `PDF2HTMLEX_PATH`
5. Value: הנתיב המלא ל-`pdf2htmlEX.exe`
6. לחץ **OK**

---

## בדיקה שהכל עובד

לאחר ההתקנה, בדוק:

```bash
# ב-Command Prompt או PowerShell:
pdf2htmlEX --version

# או אם הגדרת PDF2HTMLEX_PATH:
echo %PDF2HTMLEX_PATH%
```

---

## פתרון בעיות

### "pdf2htmlEX is not recognized"
- וודא שהוספת את התיקייה ל-PATH
- או הגדר את `PDF2HTMLEX_PATH`
- הפעל מחדש את Terminal/Command Prompt

### "Permission denied" ב-WSL
```bash
sudo chmod +x /usr/local/bin/pdf2htmlEX
```

### שגיאות בתלויות
```bash
# ב-WSL, התקן תלויות חסרות:
sudo apt-get install -f
```

---

## המלצה סופית

**למשתמש Windows:**
1. **אם יש לך WSL2** → אפשרות 2 (הכי פשוט)
2. **אם אין WSL2** → אפשרות 1 (הורדת גרסה מוכנה) או אפשרות 5 (Chocolatey)
3. **אם יש Docker** → אפשרות 4

לאחר ההתקנה, הפעל את האפליקציה מחדש והכל אמור לעבוד! 🚀

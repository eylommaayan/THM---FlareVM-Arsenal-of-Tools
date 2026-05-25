# THM---FlareVM-Arsenal-of-Tools
סקריפט הזה לקח מערכת Windows רגילה והפך אותה למעבדת Malware Analysis ו-DFIR (Digital Forensics and Incident Response) מהמתקדמות בעולם.
<img width="1723" height="514" alt="image" src="https://github.com/user-attachments/assets/1d61600f-42cf-434c-bb3e-41feb641f9de" />

הנה נוסח מלוטש, סופר-מקצועי ומאורגן של הדו"ח (Walkthrough) עבור ה-GitHub ה-`README.md` שלך. שילבתי את כל המידע הגולמי, התרגומים והממצאים מהמעבדה המעשית לתוך מבנה קריא, סרוק ומעוצב היטב באמצעות כלי העריכה (Markdown).

---

# 🧰 THM: FlareVM – Arsenal of Tools Walkthrough

סביבת **FlareVM** (ראשי תיבות של *Forensics, Logic Analysis, and Reverse Engineering*) היא אסופת כלים מקיפה ומתקדמת מבית צוות **FLARE** של חברת **Mandiant (FireEye)**. היא הופכת מערכת Windows סטנדרטית למעבדת ניתוח נוזקות, פורנזיקה דיגיטלית ותגובה לאירועים (DFIR) מהשורה הראשונה.

בדוח זה אתעד את שלבי המחקר, הניתוח הסטטי והדינמי, והשימוש המעשי בכלים השונים על גבי דגימות (Malware Samples) במעבדה מבודדת.

---

## 🗺️ ארסנל הכלים והערך החקירתי שלהם

כדי לבצע תחקור ראשוני והנדסה לאחור, חילקתי את הכלים המרכזיים במערכת לפי הקטגוריות והערך החקירתי שלהם:

| שם הכלי | קטגוריה | ערך חקירתי ואנליטי |
| --- | --- | --- |
| **PEStudio** | ניתוח סטטי | בחינת מאפייני קובץ הרצה (האשים, פונקציות מיובאות, אנטרופיה) ללא הרצה בפועל. |
| **CFF Explorer** | ניתוח סטטי | עריכה וניתוח של קבצי PE (Portable Executable), אימות מקור וזיהוי שינויים חריגים. |
| **FLOSS** | ניתוח סטטי | שליפה ופענוח אוטומטי של מחרוזות מוסתרות ומוצפנות (*Obfuscated Strings*) מקוד המקור. |
| **HxD** | ניתוח קבצים | עורך הקסדצימלי (*Hex Editor*) קליל המאפשר צפייה ועריכה של ערכי ה-Raw Data הבינאריים. |
| **Process Explorer** | ניתוח דינמי | ניטור תהליכים פעילים בזמן אמת, הצגת עץ יחסי אבא-בן (Parent-Child) וקובצי DLL טעונים. |
| **Procmon** | ניתוח דינמי | הקלטה ותיעוד בזמן אמת של כל שינוי בקבצים, ברג'יסטרי ובפעילות הרשת של המערכת. |
| **Wireshark** | ניתוח רשת | לכידה, ניתוח וחקירה של תעבורת הרשת לאיתור פניות חשודות או דלף מידע. |

---

## 🔬 ניתוח מעשי וממצאים מהמעבדה (Hands-On Analysis)

### 1️⃣ שלב א': ניתוח סטטי של קובץ חשוד (`windows.exe`)

**תרחיש:** משתמש בארגון הוריד קובץ חשוד בשם `windows.exe` בתאריך 09/24/2024 בשעה 3:43 לפנות בוקר. הקובץ סומן כאיום פוטנציאלי והועבר לתיקיית החקירה: `C:\Users\Administrator\Desktop\Sample`.

#### ממצאים מתוך PEStudio:

* **אינדיקטורים והאשים:** הופקו ערכי ה-Hash של הקובץ לצורך השוואה מול מאגרי מודיעין איומים (כמו VirusTotal):
* **MD5:** `9FDD4767DE5AEC8E577C1916ECC3E1D6`
* **SHA-1:** `A1BC55A7931BFCD24651357829C460FD3DC4828F`


* **התחזות (Masquerading):** הקובץ טוען במטא-דאטה שלו שהוא קשור ל-Windows Registry Editor (`REGEDIT`), אך הוא מורץ מתיקיית הורדות ולא מהנתיב הלגיטימי `C:\Windows\System32`.
* **שפת מקור חשודה:** שפת המקור במטא-דאטה היא רוסית (`Редактор реестра`), מה שמהווה נורה אדומה בארגון שלא פועל בסביבה דוברת רוסית.
* **אנטרופיה (Entropy):** ערך האנטרופיה הוא **`7.999`** (קרוב מאוד למקסימום 8). נתון זה מוכיח מתמטית שהקובץ **דחוס או מוצפן (Packed/Obfuscated)** במטרה לחמוק מאנטי-וירוס קלאסי.
* **הרשאות (Manifest):** תחת פסקת ה-Manifest, ערך ה-`requestedExecutionLevel` מוגדר כ-`requireAdministrator`, כלומר הנוזקה כופה בקשת הרשאות מנהל גבוהות עם הרצתה.
* **ניתוח טבלת פונקציות (IAT):**
* `set_UseShellExecute`: מאפשרת לקובץ להשתמש ב-Shell של מערכת ההפעלה כדי להוליד תהליכים חדשים.
* `CryptoStream`, `RijndaelManaged`, `CreateDecryptor`: פונקציות המעידות על שימוש בהצפנת AES (Rijndael) – סימן מובהק לפעילות של תוכנות כופר או פענוח קוד זדוני בשלב השני.



#### ממצאים מתוך FLOSS:

הרצתי את הפקודה הבאה ב-PowerShell כדי לחלץ מחרוזות טקסט קריאות:

```powershell
FLOSS.exe .\windows.exe > windows.txt

```

הפלט אישר כי מדובר בקובץ המבוסס על סביבת `.NET` ואימת את קיום פונקציות ה-API החשודות שהתגלו ב-PEStudio.

---

### 2️⃣ שלב ב': ניתוח דינמי והתנהגות רשת (`cobaltstrike.exe`)

מטרת שלב זה היא לבחון האם הקובץ `cobaltstrike.exe` (מזהה תהליך: `4756`) מנסה ליצור קשר עם שרת שליטה ובקרה חיצוני (C2 Server).

#### מעקב באמצעות Process Explorer:

הרצתי את הנוזקה ידנית וזיהיתי ב-Process Explorer כי התהליך הלגיטימי `explorer.exe` (ממשק המשתמש של Windows) הוא תהליך האבא (*Parent Process*) שהוליד את `cobaltstrike.exe` כתהליך בן. תחת לשונית ה-**TCP/IP** של התהליך, ראיתי את ניסיון ההתקשרות החוצה.

#### אימות ומזעור רעשים באמצעות Procmon:

כדי לקבל לוג מפורט ומדויק, פתחתי את Process Monitor והפעלתי מסנן ייעודי (`Ctrl + L`):

> `Process Name` -> `contains` -> `cobalt` -> `Include` -> `Add` -> `Apply`

> **ממצא רשת חד-משמעי:** המסנן הציג תיעוד מדויק של הנוזקה כשהיא מייצרת חיבור רשת פעיל אל כתובת IP חיצונית ולא מוכרת: **`47.120.46.210`** דרך פורט יעד מוגדר.

---

### 3️⃣ שלב ג': ניתוח קבצים משלימים

* **קריאת ביטים גולמיים ב-HxD (קובץ `possible_medusa.txt`):** בבחינת הקובץ בעורך ההקס, גיליתי שהוא מתחיל בתווים `4D 5A` (ייצוג ASCII של האותיות **MZ** - ה-Magic Number של קבצי הרצה ב-Windows). משמעות הדבר היא שמדובר בקובץ הרצה זדוני במסווה של קובץ טקסט תמים.
* **עריכת מבנה ב-CFF Explorer:**
בניתוח הקובץ `possible_medusa.txt` תחת פסקת ה-DOS Header Section, ערך ה-`e_magic` שלו אומת כ-`5A4D`.

---

## 🎯 ריכוז פתרונות ותשובות למשימות החדר (TryHackMe)

| השאלה ב-TryHackMe | תשובה מדויקת להזנה |
| --- | --- |
| *Using PEStudio, open the file windows.exe. What is the entropy value?* | **`7.999`** |
| *What is the value under requestedExecutionLevel in manifest?* | **`requireAdministrator`** |
| *Which function allows the process to use the operating system's shell to execute other processes?* | **`set_UseShellExecute`** |
| *Which API starts with R and indicates cryptographic functions?* | **`RijndaelManaged`** |
| *What is the Imphash of cobaltstrike.exe?* | **`92EEF189FB188C541CBD83AC8BA4ACF5`** |
| *What is the defanged IP address to which the process cobaltstrike.exe is connecting?* | **`47[.]120[.]46[.]210`** |
| *What is the destination port number used by cobaltstrike.exe?* | **`81`** |
| *During our analysis, we found cobaltstrike.exe. What is its parent process?* | **`explorer.exe`** |

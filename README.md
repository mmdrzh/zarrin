# زرین (Zarrin)

پنل تکمیلی برای [PasarGuard](https://github.com/PasarGuard/panel): کنار اینباندهای خود پاسارگاد، به همان کاربرها امکان اتصال با **IKEv2** (و به‌زودی **L2TP/IPsec**، **OpenVPN** و **WireGuard**) را می‌دهد؛ با محیط مدیریت وب فارسی.

- کاربرها فقط در پاسارگاد ساخته می‌شوند. یوزرنیم همان نام اکانت است و رمز یک عدد ۶ رقمی است که از UUID کاربر ساخته می‌شود (با revoke لینک ساب عوض می‌شود).
- تاریخ انقضا، حجم و وضعیت کاربر از دیتابیس پاسارگاد خوانده می‌شود و مصرف هر کاربر به حجمش در پاسارگاد اضافه می‌شود (زیر همان نود و با ضریب نود).
- کاملاً جدا از پاسارگاد نصب می‌شود (`/opt/zarrin` روی پنل و `/opt/zarrin-agent` روی نودها). آپدیت پاسارگاد چیزی از زرین پاک نمی‌کند.
- اضافه کردن نود جدید با یک دستور که پنل می‌سازد.
- بکاپ ساعتی به تلگرام، و ریستور از داخل پنل.
- کاربران آنلاین همه‌ی نودها، قطع و مسدود کردن موقت.
- ورود ادمین با رمز + کد دومرحله‌ای (TOTP)، گزارش فعالیت.

## ساختار

```
panel/        پنل (FastAPI + Vue) — روی سرور پاسارگاد
  zarrin/     سرور: API مدیریت، API نودها، بکاپ، گواهی SSL
  web/        رابط کاربری فارسی
  subpage/    کارت IKEv2 در صفحه‌ی ساب پاسارگاد
agent/        ایجنت نود (strongSwan و ...) — پنل آن را برای نودها می‌فرستد
install.sh    نصب پنل
zarrin.sh     دستور مدیریتی روی سرور (zarrin)
```

## نصب پنل (روی سرور پاسارگاد)

پیش‌نیاز: پاسارگاد با دیتابیس PostgreSQL/TimescaleDB، و یک ساب‌دامین که به IP همین سرور اشاره کند (ابر خاکستری).

ریپو خصوصی است؛ یکی از این دو راه برای دسترسی سرور به ریپو:
- **Deploy key**: روی سرور `ssh-keygen -t ed25519` و کلید عمومی را در GitHub → Settings → Deploy keys اضافه کنید.
- **توکن**: یک Fine-grained token فقط با دسترسی Contents: Read روی همین ریپو، و `git clone https://<TOKEN>@github.com/mmdrzh/zarrin.git /opt/zarrin`

```bash
sudo git clone git@github.com:mmdrzh/zarrin.git /opt/zarrin
sudo /opt/zarrin/install.sh
```

نصب‌کننده دامنه، پورت و نام ادمین را می‌پرسد و در پایان رمز ادمین را نشان می‌دهد. پورت پنل را در فایروال باز کنید.

## اضافه کردن نود

در پنل: **نودها ← افزودن نود** ← دستور تک‌خطی را روی سرور نود با root اجرا کنید:

```bash
curl -fsSL https://<panel-domain>:<port>/join/<token> | sudo bash
```

نودها به GitHub نیازی ندارند؛ همه‌چیز را از پنل می‌گیرند. IP نود را به رکورد DNS دامنه‌ی IKEv2 هم اضافه کنید (ابر خاکستری).

## دستورهای سرور پنل

```
zarrin status            وضعیت
zarrin logs              لاگ‌ها
zarrin update            آپدیت از GitHub (پاسارگاد دست نمی‌خورد)
zarrin admin <user>      ساخت ادمین یا ریست رمز (2FA خاموش می‌شود)
zarrin subpage           افزودن کارت IKEv2 به صفحه‌ی ساب (--remove برای حذف)
```

روی نود: `docker logs -f zarrin-agent` و `docker exec zarrin-agent swanctl --list-sas`

## پورت‌ها

| کجا | پورت | برای |
|---|---|---|
| پنل | TCP پورت زرین | محیط مدیریت و ارتباط نودها |
| پنل | TCP 80 | گرفتن/تمدید گواهی Let's Encrypt |
| نود | UDP 500, 4500 | IKEv2 |
| نود | TCP 80 | تمدید گواهی IKEv2 |

## حذف

```bash
# روی هر نود
cd /opt/zarrin-agent && docker compose down && cd / && rm -rf /opt/zarrin-agent
# روی پنل
zarrin subpage --remove
cd /opt/zarrin && docker compose down && systemctl disable --now zarrin-restore.path
sudo docker exec <timescaledb-container> psql -U <db-user> -d <db> -c "DROP OWNED BY zarrin; DROP ROLE zarrin;"
rm -rf /opt/zarrin /usr/local/bin/zarrin
```

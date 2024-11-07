# Təhlükəsizlik Yoxlama Skripti

Bu Python skripti Windows sistemində təhlükəsizlik yoxlamaları aparmaq üçün hazırlanmışdır. Skript aşağıdakı funksiyaları yerinə yetirir:

- Sistem resurslarını yoxlamaq (CPU, RAM, Disk istifadəsi).
- Təhlükəsizlik event loglarını oxumaq.
- Şübhəli prosesləri tapmaq (virus, malware, ransomware və s.).
- Şübhəli faylları tapmaq (temp qovluğundakı şübhəli fayllar).
- Açıq portları yoxlamaq (TCP və UDP).
- Firewall statusunu yoxlamaq.
- Windows-da təhlükəsizlik yeniləmələrini yoxlamaq.
- Hesabatın avtomatik yaradılması və faylda saxlanılması.

## Quraşdırma

1. Python 3.x versiyasının quraşdırıldığından əmin olun.
2. Aşağıdakı Python kitabxanalarının quraşdırılması lazımdır:

```bash

pip install psutil pywin32

```
# Tool istifadəsi
```bash
git clone https://github.com/cyberprogramming1/Security-Monitor.git
```
# Tool'u run eləmək  
```bash
python security_monitor.py
```
or 
```bash
security_monitor.exe
```
## Skriptin İstifadəsi

1. Skripti administrator olaraq işə salın.
2. Skript, verilən portları yoxlayacaq, təhlükəsizlik loglarını oxuyacaq, şübhəli prosesləri və faylları araşdıracaq.
3. Təhlükəsizlik hesabatı yaradılacaq və `security_report_<tarix>.txt` adlı faylda saxlanılacaq.

## Əsas Funksiyalar

- **`get_local_ip()`**: Kompüterin yerli IP ünvanını tapır.
- **`check_ports()`**: Verilən portları yoxlayır və açıq olanları qaytarır.
- **`get_event_logs()`**: Təhlükəsizlik event loglarını oxuyur.
- **`check_suspicious_processes()`**: Şübhəli prosesləri tapır.
- **`check_suspicious_files()`**: Şübhəli faylları tapır.
- **`check_firewall_status()`**: Firewall statusunu yoxlayır.
- **`check_system_resources()`**: CPU, RAM və disk istifadəsini yoxlayır.
- **`check_security_updates()`**: Təhlükəsizlik yeniləmələrinin olub-olmamasını yoxlayır.
- **`check_ports_multithreaded()`**: Portları paralel olaraq yoxlayır.
- **`generate_security_report()`**: Təhlükəsizlik hesabatı yaradır və faylda saxlayır.

## Təhlükəsizlik Xəbərdarlıqları

- Skripti administrator olaraq işə saldığınızdan əmin olun.
- Skriptin nəticələrinə əsasən təhlükəsizlik tədbirlərini görməlisiniz.
- Yoxlama zamanı kritik proseslər və fayllar tapıla bilər. Bu zaman tədbir görmək tövsiyə olunur.

## Qeyd

Bu skript yalnız Windows sistemlərində işləyir və bəzi funksiyalar yalnız administrator hüquqları ilə işləyir.

---


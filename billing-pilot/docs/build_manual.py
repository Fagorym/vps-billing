from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'output/pdf/fossbilling-vps-guide.pdf'
OUT.parent.mkdir(parents=True, exist_ok=True)
FONT_ROOT = Path('/System/Library/Fonts/Supplemental')
pdfmetrics.registerFont(TTFont('Guide', str(FONT_ROOT / 'Arial.ttf')))
pdfmetrics.registerFont(TTFont('GuideBold', str(FONT_ROOT / 'Arial Bold.ttf')))
pdfmetrics.registerFontFamily('Guide', normal='Guide', bold='GuideBold')

W, H = A4
M = 43
CW = W - 2 * M
INK = colors.HexColor('#17283B')
MUTED = colors.HexColor('#586879')
TEAL = colors.HexColor('#007F78')
PALE = colors.HexColor('#E8F5F2')
BLUE = colors.HexColor('#2477B8')
LINE = colors.HexColor('#DCE3EA')
BG = colors.HexColor('#F4F7FA')
ORANGE = colors.HexColor('#A85A00')
CREAM = colors.HexColor('#FFF2DA')
WHITE = colors.white
C = canvas.Canvas(str(OUT), pagesize=A4)
C.setTitle('FOSSBilling: клиенты, VPS и оплата')
C.setAuthor('Safehost / пилот Proxmox')
C.setSubject('Пошаговая инструкция администратора. FOSSBilling 0.8.8, тестовый режим.')


def text(value, x, top, size=11, bold=False, color=INK):
    value = value.replace('₽', 'руб.')
    C.setFillColor(color)
    C.setFont('GuideBold' if bold else 'Guide', size)
    C.drawString(x, H - top - size, value)


def para(value, x, top, width=CW, size=11, color=INK, leading=None):
    value = value.replace('₽', 'руб.')
    st = ParagraphStyle('p', fontName='Guide', fontSize=size,
                        leading=leading or size * 1.38, textColor=color,
                        alignment=TA_LEFT, spaceAfter=0)
    p = Paragraph(value, st)
    _, h = p.wrap(width, H)
    if top + h > H - 49:
        raise ValueError(f'Page overflow: {value[:70]} at {top + h}')
    p.drawOn(C, x, H - top - h)
    return h


def rect(x, top, width, height, fill=WHITE, stroke=LINE, radius=10):
    C.setFillColor(fill)
    C.setStrokeColor(stroke or fill)
    C.setLineWidth(0.7)
    C.roundRect(x, H - top - height, width, height, radius, stroke=bool(stroke), fill=1)


def rule(top):
    C.setStrokeColor(LINE)
    C.line(M, H - top, W - M, H - top)


def badge(value, x, top, width=110, fill=PALE, fg=TEAL):
    rect(x, top, width, 23, fill, None, 6)
    text(value, x + 9, top + 5, 9, True, fg)


def step(number, title, detail, top):
    C.setFillColor(TEAL)
    C.circle(M + 11, H - top - 11, 11, fill=1, stroke=0)
    C.setFillColor(WHITE)
    C.setFont('GuideBold', 10)
    C.drawCentredString(M + 11, H - top - 14.5, str(number))
    title_h = para('<b>' + escape(title) + '</b>', M + 34, top - 1, CW - 34, 11)
    detail_h = para(detail, M + 34, top + title_h + 3, CW - 34, 10.5, MUTED)
    return top + title_h + detail_h + 14


def note(title, body, top, warn=False):
    fill, fg = (CREAM, ORANGE) if warn else (PALE, TEAL)
    body_h = Paragraph(body, ParagraphStyle('n', fontName='Guide', fontSize=10.4,
                       leading=14.2, textColor=INK)).wrap(CW - 26, H)[1]
    h = body_h + 45
    rect(M, top, CW, h, fill, None)
    text(title, M + 13, top + 10, 11, True, fg)
    para(body, M + 13, top + 31, CW - 26, 10.4, INK, 14.2)
    return top + h


def page(number, title, subtitle):
    C.setFillColor(TEAL)
    C.rect(0, H - 6, W, 6, fill=1, stroke=0)
    text('SAFEHOST  /  ПИЛОТ VPS', M, 24, 9, True, TEAL)
    text('FOSSBilling 0.8.8', W - M - 98, 24, 9, color=MUTED)
    text(title, M, 58, 23, True)
    para(subtitle, M, 96, CW, 11, MUTED)
    rule(H - 41)
    text('Инструкция администратора  •  11.10.2026', M, H - 29, 8.2, color=MUTED)
    text(f'{number} / 7', W - M - 25, H - 29, 8.2, color=MUTED)


def finish():
    C.showPage()


def form(top, title, fields, button, height=None):
    """Vector illustration of selected fields, explicitly labelled as a diagram."""
    h = height or (64 + len(fields) * 52)
    rect(M, top, CW, h, BG)
    text('СХЕМА ФОРМЫ / ПРИМЕР ЗАПОЛНЕНИЯ', M + 15, top + 11, 8, True, MUTED)
    text(title, M + 15, top + 31, 13, True)
    y = top + 59
    for label, value in fields:
        text(label, M + 16, y, 9, True, MUTED)
        rect(M + 16, y + 15, CW - 32, 26, WHITE, LINE, 4)
        text(value, M + 24, y + 22, 10)
        y += 52
    rect(W - M - 153, top + h - 38, 137, 27, TEAL, None, 5)
    text(button, W - M - 142, top + h - 31, 10, True, WHITE)
    return top + h


def arrow(x1, y1, x2, y2, color=TEAL):
    C.setStrokeColor(color)
    C.setFillColor(color)
    C.setLineWidth(1.8)
    C.line(x1, H - y1, x2, H - y2)
    p = C.beginPath()
    if abs(x2 - x1) >= abs(y2 - y1):
        sign = 1 if x2 >= x1 else -1
        p.moveTo(x2, H - y2)
        p.lineTo(x2 - 6 * sign, H - y2 + 3.3)
        p.lineTo(x2 - 6 * sign, H - y2 - 3.3)
    else:
        sign = 1 if y2 >= y1 else -1
        p.moveTo(x2, H - y2)
        p.lineTo(x2 - 3.3, H - y2 + 6 * sign)
        p.lineTo(x2 + 3.3, H - y2 + 6 * sign)
    p.close()
    C.drawPath(p, fill=1, stroke=0)


def server(x, top, width, title, subtitle, fill=BG):
    rect(x, top, width, 86, fill)
    for i in range(3):
        rect(x + 13, top + 13 + i * 9, 29, 6, TEAL, None, 2)
    text(title, x + 13, top + 46, 11, True)
    text(subtitle, x + 13, top + 64, 9, color=MUTED)


# 1. Overview.
page(1, 'Клиент → заказ → оплата → VPS',
     'Как завести клиента, выдать ему VM и учитывать оплату в нашем пилоте на Selectel.')
badge('ТЕСТОВЫЙ РЕЖИМ', M, 132, 132)
badge('Ubuntu 24.04', M + 142, 132, 107, BG, MUTED)
badge('Proxmox + NAT', M + 259, 132, 118, BG, MUTED)
labels = [('Клиент', 'Учетная запись'), ('Заказ', 'Тариф + доступ'),
          ('Оплата', 'Счет или баланс'), ('VM', 'Создание в Proxmox')]
box_w = (CW - 39) / 4
for i, (title, subtitle) in enumerate(labels):
    x = M + i * (box_w + 13)
    rect(x, 182, box_w, 88, PALE if i == 3 else BG)
    text(f'0{i+1}', x + 12, 193, 10, True, TEAL)
    text(title, x + 12, 215, 14, True)
    para(escape(subtitle), x + 12, 239, box_w - 20, 8.7, MUTED, 11)
    if i < 3:
        arrow(x + box_w + 2, 227, x + box_w + 11, 227)
para('<b>Биллинг хранит клиента, счета и срок услуги.</b> Наш адаптер создает и управляет VM в Proxmox. '
     'После оплаты первого счета появляется VPS; оплата продления продлевает ту же VM.', M, 294)
text('Тарифы пилота', M, 360, 15, True)
rows = [('Mini', '1 vCPU', '1 ГБ', '20 ГБ', '390 ₽'),
        ('Small', '2 vCPU', '2 ГБ', '50 ГБ', '650 ₽'),
        ('Medium', '4 vCPU', '4 ГБ', '80 ГБ', '1 100 ₽')]
cols = [M + 13, M + 116, M + 219, M + 313, M + 410]
rect(M, 389, CW, 33, INK, None, 6)
for x, v in zip(cols, ['Тариф', 'CPU', 'RAM', 'Диск', 'За месяц']):
    text(v, x, 399, 10, True, WHITE)
for i, row in enumerate(rows):
    rect(M, 429 + i * 38, CW, 33, BG if i % 2 == 0 else WHITE, None, 4)
    for j, (x, v) in enumerate(zip(cols, row)):
        text(v, x, 438 + i * 38, 10.5, j in (0, 4))
note('Два способа учесть поступление',
     '<b>Конкретный счет:</b> Mark as Paid. <b>Аванс клиента:</b> Add Funds. '
     'Одно поступление учитываем одним способом.', 565)
para('Админка биллинга: <link href="https://80.249.131.4/admin" color="#2477B8"><b>https://80.249.131.4/admin</b></link>. '
     'Кабинет: <link href="https://80.249.131.4/" color="#2477B8">https://80.249.131.4/</link>. '
     'Открывай в браузере; SSH-туннель не нужен. '
     'Администратор: <b>admin@example.test</b>. Пароль прежний, хранится локально в '
     'billing-pilot/.secrets/bootstrap.json; в документ он не включен.', M, 677, CW, 10.2, MUTED)
para('Формы показаны схематично; на странице 7 - скриншот Selectel. Примеры заполнения '
     'не создают клиентов и не проводят платежи.', M, 743, CW, 9.2, MUTED)
finish()


# 2. Client.
page(2, '1. Завести нового клиента', 'Все действия выполняются в админке FOSSBilling.')
y = 139
for n, title, body in [
    (1, 'Clients → New Client', 'Открой список клиентов и форму создания учетной записи.'),
    (2, 'Имя, email, пароль', 'Задай пароль кабинета сразу. Укажи email клиента на существующем домене.'),
    (3, 'Currency: RUB; Status: Active', 'Валюта нужна для пополнения баланса и выставления счетов.'),
    (4, 'Отключи Send client welcome email и сохрани', 'Исходящие письма в пилоте отключены. Не рассчитывай на письмо для установки пароля.'),
]:
    y = step(n, title, body, y)
form(y + 12, 'Create a New Client', [
    ('First Name / Last Name', 'Иван / Петров'),
    ('Email Address / Password', 'client@gmail.com / задан вручную'),
    ('Currency / Status', 'RUB / Active'),
    ('Send client welcome email', 'Выключено'),
], 'Create', height=310)
note('Проверка результата', 'Клиент появился в списке. В его карточке доступны услуги, счета и вкладка '
     '<b>Payments</b>. Для заказа нажми <b>Login to Client Area</b>.', y + 337)
finish()


# 3. VM.
page(3, '2. Завести клиенту новую VM', 'Один заказ VPS - одна VM. Для каждой следующей VM оформляй отдельный заказ.')
y = 139
for n, title, body in [
    (1, 'Clients → клиент → Login to Client Area', 'Откроется кабинет выбранного клиента.'),
    (2, 'Каталог → тариф → период 1 месяц', 'Выбери VPS Mini, Small или Medium. В текущем пилоте установлена Ubuntu 24.04.'),
    (3, 'Выбери пароль или SSH-ключ', 'Для временного пароля оставь SSH-поле пустым. Для входа по ключу вставь <b>ssh-ed25519</b> из файла <b>.pub</b>.'),
    (4, 'Checkout → ТЕСТ - без списаний', 'Оформи заказ. Если баланса хватает, счет оплатится автоматически. Иначе он ожидает оплаты.'),
    (5, 'Оплати счет → Services → услуга', 'VM создается автоматически. В услуге появятся адрес, порт и пользователь <b>vpsadmin</b>. Дождись настройки Ubuntu.'),
]:
    y = step(n, title, body, y)
form(y + 8, 'Заказ VPS Mini - TEST', [
    ('Период', '1 месяц / 390 ₽'),
    ('Публичный SSH-ключ (необязательно)', '(пусто) - выдать временный пароль'),
], 'Checkout', height=191)
note('SSH и сеть', 'Сейчас VPS используют общий публичный адрес <b>80.249.131.4</b> и разные SSH-порты. '
     'Бери порт из карточки услуги. Для отдельного публичного IP требуется сеть Selectel; см. страницу 7.', y + 217)
para('Для пароля нажми в услуге <b>«Показать начальный пароль»</b>. При первом SSH-входе задай '
     'свой новый пароль. После смены начальный пароль из кабинета больше не действует. '
     'Повторная активация не сбрасывает доступ.', M, y + 306, CW, 10, MUTED)
finish()


# 4. Direct invoice payment.
page(4, '3. Провести оплату счета', 'Этот путь подходит, когда поступление относится к конкретной VM и конкретному счету.')
y = 139
for n, title, body in [
    (1, 'Invoicing → Invoices → неоплаченный счет', 'Проверь клиента, сумму, валюту и услугу.'),
    (2, 'Mark as Paid', 'Для пилота это ручное подтверждение тестовой оплаты.'),
    (3, 'Transaction ID → Submit', 'Используй уникальный идентификатор. Пример: TEST-CLIENT2-001.'),
    (4, 'Проверь Paid и состояние услуги', 'Связанные задачи запускаются автоматически: создание VM или продление существующей.'),
]:
    y = step(n, title, body, y)
form(y + 12, 'Mark as Paid / Enter Custom Transaction ID', [
    ('Проверенный счет', 'Клиент №2 / VPS Mini / 390 ₽ / Unpaid'),
    ('Transaction ID', 'TEST-CLIENT2-001'),
], 'Submit', height=195)
box_y = y + 226
rect(M, box_y, 144, 54, BG)
text('Unpaid', M + 14, box_y + 9, 12, True, MUTED)
text('Оплата ожидается', M + 14, box_y + 29, 9, color=MUTED)
arrow(M + 154, box_y + 27, M + 178, box_y + 27)
rect(M + 188, box_y, 144, 54, PALE)
text('Paid', M + 202, box_y + 9, 12, True, TEAL)
text('Задача активации', M + 202, box_y + 29, 9, color=MUTED)
arrow(M + 342, box_y + 27, M + 366, box_y + 27)
rect(M + 376, box_y, CW - 376, 54, PALE)
text('Active', M + 389, box_y + 9, 12, True, TEAL)
text('VM создана', M + 389, box_y + 29, 9, color=MUTED)
note('Одно поступление - одна запись', 'Если отмечаешь оплату этого счета, не зачисляй ту же сумму '
     'через Add Funds. В нашей форме отдельная галочка Execute related tasks не требуется.', box_y + 75, True)
finish()


# 5. Wallet.
page(5, '4. Пополнить баланс клиента', 'Баланс - внутренний учет аванса. Сам перевод денег происходит во внешнем платежном сервисе.')
y = 139
for n, title, body in [
    (1, 'Clients → клиент → Payments', 'Открой историю баланса нужного клиента.'),
    (2, 'Add Funds for Client → Amount', 'Введи сумму поступления в рублях. Для теста, например, 1000.'),
    (3, 'Description → Add Funds', 'Запиши основание и ID внешней операции. До зачисления проверь, что этого платежа еще нет в истории.'),
    (4, 'Проверь баланс и неоплаченные счета', 'Каждые 5 минут биллинг пробует оплатить счета из баланса. На счет должна хватать полная сумма.'),
]:
    y = step(n, title, body, y)
form(y + 10, 'Payments / Add Funds for Client', [
    ('Amount', '1000 RUB'),
    ('Description', 'Тестовое пополнение / TEST-TOPUP-001'),
], 'Add Funds', height=191)
ledger_y = y + 220
rect(M, ledger_y, CW, 65, PALE, None)
text('+1 000 ₽', M + 18, ledger_y + 11, 19, True, TEAL)
text('Зачислено', M + 18, ledger_y + 40, 10, color=MUTED)
text('-390 ₽', M + 202, ledger_y + 11, 19, True)
text('Счет Mini', M + 202, ledger_y + 40, 10, color=MUTED)
text('610 ₽', M + 386, ledger_y + 11, 19, True, TEAL)
text('Остаток', M + 386, ledger_y + 40, 10, color=MUTED)
note('Пополнение и продление - разные события', 'Дни услуги добавляются после оплаты ее счета. '
     'У клиента с несколькими VM баланс общий. Повторный ручной Add Funds может зачислить один перевод дважды.', ledger_y + 83, True)
finish()


# 6. External payment and renewal.
page(6, '5. Оплата вне FOSSBilling', 'Для старта подтверждаем поступления вручную. Затем подключаем интеграцию с платежным сервисом.')
rect(M, 139, CW, 62, INK, None)
text('Платежный сервис подтвердил поступление', M + 15, 153, 14, True, WHITE)
text('ID операции + сумма + валюта + клиент или номер счета', M + 15, 178, 10, color=WHITE)
branch_w = (CW - 22) / 2
for x in (M, M + branch_w + 22):
    arrow(x + branch_w / 2, 204, x + branch_w / 2, 227)
rect(M, 234, branch_w, 158, BG)
rect(M + branch_w + 22, 234, branch_w, 158, PALE)
text('Оплата конкретной VM', M + 14, 251, 13, True)
para('Платеж привязан к счету.<br/><br/><b>Invoices → Mark as Paid</b><br/><br/>'
     'Создание или продление VM.', M + 14, 282, branch_w - 28, 10.7)
text('Аванс на услуги клиента', M + branch_w + 36, 251, 13, True)
para('Платеж привязан к клиенту.<br/><br/><b>Payments → Add Funds</b><br/><br/>'
     'Биллинг оплачивает счета из баланса.', M + branch_w + 36, 282, branch_w - 28, 10.7)
note('Рекомендация для пилота', 'Используй первый путь для оплаты определенного счета, второй - для аванса '
     'на одну или несколько VM. Не проводи одно поступление по обеим веткам.', 413)
text('Что произойдет при продлении', M, 506, 14, True)
y = 535
for n, title, body in [
    (1, 'За 14 дней до конца периода', 'Биллинг выставляет счет продления. При достаточном балансе он может оплатиться заранее.'),
    (2, 'Период закончился, счет не оплачен', 'Фоновая задача приостанавливает VM. Диск сохраняется.'),
    (3, 'Оплачен счет продления', 'Биллинг продлевает услугу и возобновляет приостановленную VM.'),
]:
    y = step(n, title, body, y)
para('<b>Следующий этап:</b> webhook от сервиса автоматически подтверждает счет или пополняет баланс. '
     'Интеграция проверяет подлинность уведомления, сумму и валюту, а повторный ID операции не учитывает дважды. '
     'Эта интеграция в пилоте пока не подключена.', M, y + 9, CW, 10.1, MUTED)
finish()


# 7. Checks and current network.
page(7, '6. Проверки и текущая сеть', 'Что проверить после выдачи VPS. Отдельные публичные IP пока отложены; используем NAT.')
note('Счет Paid, но VPS еще не готов', 'Открой <b>Failed invoice items</b> и задачу активации. '
     'После устранения ошибки повтори задачу того же заказа. Не создавай новый заказ для обхода сбоя: '
     'у старого уже может быть выделена VM.', 139, True)
para('<b>Active не означает мгновенно готовый SSH.</b> При первом старте cloud-init настраивает Ubuntu '
     'и выбранный способ входа. Проверь SSH по команде из услуги. Fingerprint первого подключения сверяется '
     'через консоль VM: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub.', M, 246, CW, 10.5)
text('Почему сейчас используем NAT', M, 332, 16, True)
image_path = ROOT / 'billing-pilot/docs/assets/selectel-public-subnets.png'
from reportlab.lib.utils import ImageReader
image = ImageReader(str(image_path))
iw, ih = image.getSize()
image_h = CW * ih / iw
C.drawImage(image, M, H - 366 - image_h, width=CW, height=image_h, mask='auto')
para('Скриншот панели Selectel, предоставлен 11.10.2026. Фильтры: все пулы, типы и услуги.',
     M, 371 + image_h, CW, 8.8, MUTED)
y = 402 + image_h
for n, title, body in [
    (1, '80.249.131.4 / SPB-4 - адрес нашего хоста', 'Proxmox использует этот публичный IPv4. Клиентские VM доступны через него по разным SSH-портам.'),
    (2, '188.124.47.155 / SPB-5 - другой пул', 'Адрес другого пула нельзя использовать на нашем сервере в SPB-4.'),
]:
    y = step(n, title, body, y)
para('<b>Решение для пилота:</b> выделенную публичную подсеть пока не заказываем. '
     'Клиенту передаем SSH-команду из карточки услуги. VM с отдельным публичным IP не создана.',
     M, y + 7, CW, 10, MUTED)
para('Источник ограничения по пулам: <link href="https://docs.selectel.ru/dedicated/networks/public-networks-and-subnets/" '
     'color="#2477B8">документация Selectel</link>. '
     'Названия форм и обработка баланса проверены по установленному FOSSBilling 0.8.8.',
     M, y + 64, CW, 9.1, MUTED)
finish()

C.save()
print(OUT)

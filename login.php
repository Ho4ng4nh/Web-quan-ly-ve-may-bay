<?php
session_start();
require_once 'db.php';

// PHPMailer
require 'PHPMailer/Exception.php';
require 'PHPMailer/PHPMailer.php';
require 'PHPMailer/SMTP.php';
use PHPMailer\PHPMailer\PHPMailer;

// =============================
// TRẠNG THÁI FORM
// =============================
$activeTab   = 'login';
$login_error = '';
$reg_error   = '';
$msg         = '';
$msgType     = 'info';
$step        = $_SESSION['reset_step'] ?? 1;

// =============================
// ĐĂNG NHẬP
// =============================
if (isset($_POST['form_type']) && $_POST['form_type'] === 'login') {
    $activeTab  = 'login';
    $loginInput = trim($_POST['login_input'] ?? '');
    $password   = $_POST['password'] ?? '';

    if ($loginInput && $password) {
        $q = $conn->prepare("
            SELECT tk.MaTK, tk.Password, kh.MaKH, kh.TenKH 
            FROM TaiKhoan tk
            LEFT JOIN KhachHang kh ON tk.MaTK = kh.MaTK
            WHERE (tk.TenDangNhap = ? OR kh.Email = ?)
              AND tk.VaiTro = 'User'
        ");
        $q->execute([$loginInput, $loginInput]);
        $u = $q->fetch(PDO::FETCH_ASSOC);

        if ($u && password_verify($password, $u['Password'])) {
            $_SESSION['MaKH']  = $u['MaKH'];
            $_SESSION['HoTen'] = $u['TenKH'];
            header("Location: home.php");
            exit();
        } else {
            $login_error = "Sai tên đăng nhập hoặc mật khẩu!";
        }
    } else {
        $login_error = "Vui lòng nhập đầy đủ thông tin.";
    }
}

// =============================
// ĐĂNG KÝ
// =============================
if (isset($_POST['form_type']) && $_POST['form_type'] === 'register') {
    $activeTab = 'register';

    $hoten = trim($_POST['hoten'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $sdt   = trim($_POST['sdt'] ?? '');
    $user  = trim($_POST['ten_dang_nhap'] ?? '');
    $mk    = $_POST['mat_khau'] ?? '';
    $cccd  = trim($_POST['so_cccd'] ?? '');
    $dob   = $_POST['ngaysinh'] ?? '';

    $err = [];

    $q = $conn->prepare("SELECT MaTK FROM TaiKhoan WHERE TenDangNhap=?");
    $q->execute([$user]);
    if ($q->fetch()) $err[] = "Tên đăng nhập đã tồn tại!";

    $q = $conn->prepare("SELECT Email,SDT,SoCCCD FROM KhachHang WHERE Email=? OR SDT=? OR SoCCCD=?");
    $q->execute([$email,$sdt,$cccd]);
    while ($r = $q->fetch(PDO::FETCH_ASSOC)) {
        if ($r['Email']  == $email) $err[] = "Email đã được sử dụng!";
        if ($r['SDT']    == $sdt)   $err[] = "Số điện thoại đã tồn tại!";
        if ($r['SoCCCD'] == $cccd)  $err[] = "CCCD / Passport đã tồn tại!";
    }

    if ($err) {
        $reg_error = implode("<br>", $err);
    } else {
        $conn->beginTransaction();

        $pass = password_hash($mk, PASSWORD_DEFAULT);
        $conn->prepare("INSERT INTO TaiKhoan (TenDangNhap, Password, VaiTro) VALUES (?,?, 'User')")
             ->execute([$user,$pass]);
        $id = $conn->lastInsertId();

        $conn->prepare("INSERT INTO KhachHang (MaTK, TenKH, Email, SDT, SoCCCD, NgaySinh)
                        VALUES (?,?,?,?,?,?)")
             ->execute([$id,$hoten,$email,$sdt,$cccd,$dob]);

        $conn->commit();
        header("Location: login.php");
        exit();
    }
}

// =============================
// QUÊN MẬT KHẨU
// =============================
if (isset($_POST['action'])) {
    $activeTab = 'forgot';

    if ($_POST['action'] == 'send_otp') {
        $email = trim($_POST['email'] ?? '');
        $q = $conn->prepare("SELECT MaKH,TenKH,MaTK FROM KhachHang WHERE Email=?");
        $q->execute([$email]);
        $u = $q->fetch(PDO::FETCH_ASSOC);

        if ($u) {
            $otp = rand(100000,999999);
            $_SESSION['reset_otp']   = $otp;
            $_SESSION['reset_email'] = $email;
            $_SESSION['reset_matk']  = $u['MaTK'];

            $mail = new PHPMailer(true);
            try {
                $mail->isSMTP();
                $mail->Host       = 'smtp.gmail.com';
                $mail->SMTPAuth   = true;
                $mail->Username   = 'vinhroy1811@gmail.com';
                $mail->Password   = 'wvgdpbzxhgzmnxzk';
                $mail->SMTPSecure = 'tls';
                $mail->Port       = 587;
                $mail->CharSet    = 'UTF-8';

                $mail->setFrom($mail->Username,'WL Airline');
                $mail->addAddress($email, $u['TenKH']);
                $mail->isHTML(true);
                $mail->Subject = "Mã OTP khôi phục mật khẩu";
                $mail->Body    = "<p>Xin chào <b>{$u['TenKH']}</b>, mã OTP của bạn là:</p><h2>$otp</h2>";

                $mail->send();
                $_SESSION['reset_step'] = 2;
                $step    = 2;
                $msg     = "OTP đã gửi tới email.";
                $msgType = "success";
            } catch(Exception $e) {
                $msg     = "Không gửi được email, vui lòng thử lại.";
                $msgType = "danger";
            }
        } else {
            $msg     = "Email chưa được đăng ký.";
            $msgType = "danger";
        }
    }

    if ($_POST['action'] == 'verify_otp') {
        if ($_POST['otp'] == ($_SESSION['reset_otp'] ?? null)) {
            $_SESSION['reset_step'] = 3;
            $step    = 3;
            $msg     = "Xác thực thành công, hãy đặt mật khẩu mới.";
            $msgType = "success";
        } else {
            $msg     = "Mã OTP không chính xác!";
            $msgType = "danger";
            $step    = 2;
        }
    }

    if ($_POST['action'] == 'reset_pass') {
        $new = $_POST['new_pass'] ?? '';
        $rep = $_POST['confirm_pass'] ?? '';
        if ($new === $rep) {
            $hash = password_hash($new, PASSWORD_DEFAULT);
            $conn->prepare("UPDATE TaiKhoan SET Password=? WHERE MaTK=?")
                 ->execute([$hash, $_SESSION['reset_matk']]);

            unset($_SESSION['reset_step'], $_SESSION['reset_otp'], $_SESSION['reset_email'], $_SESSION['reset_matk']);
            $msg     = "Đổi mật khẩu thành công! Bạn có thể đăng nhập lại.";
            $msgType = "success";
            $step    = 4;
        } else {
            $msg     = "Mật khẩu nhập lại không khớp!";
            $msgType = "danger";
            $step    = 3;
        }
    }
}
if ($step > 1) $activeTab = 'forgot';
?>
<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<title>WL Airline - Login</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet"
      href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
<link href="https://fonts.googleapis.com/css2?family=Be+Vietnam+Pro:wght@300;400;500;600&display=swap" rel="stylesheet">

<style>
:root{
    --glass-top: rgba(255,255,255,0.10);
    --glass-bot: rgba(255,255,255,0.30);
    --card-border: rgba(255,255,255,0.55);

    --text-main:#0f172a;
    --text-muted:#6b7280;
    --primary:#ef2947;
    --primary-soft:#f97316;
    --blue:#38bdf8;
}

*{box-sizing:border-box;}
body{
    margin:0;
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    font-family:'Be Vietnam Pro',system-ui,sans-serif;
    background:url('images/anenmb.png') center/cover no-repeat fixed;
}

/* ==== ANIMATIONS ==== */
@keyframes shellIn{
    0%{opacity:0; transform: translateY(30px) scale(.96);}
    100%{opacity:1; transform: translateY(0) scale(1);}
}
@keyframes leftIn{
    0%{opacity:0; transform: translateX(-20px);}
    100%{opacity:1; transform: translateX(0);}
}
@keyframes rightIn{
    0%{opacity:0; transform: translateX(20px);}
    100%{opacity:1; transform: translateX(0);}
}
@keyframes panelIn{
    0%{opacity:0; transform: translateY(8px);}
    100%{opacity:1; transform: translateY(0);}
}

/* CARD 2 CỘT */
.auth-shell{
    width:92%;
    max-width:900px;
    border-radius:34px;
    background:linear-gradient(140deg,var(--glass-top),var(--glass-bot));
    border:1px solid var(--card-border);
    box-shadow:0 30px 90px rgba(15,23,42,0.9);
    backdrop-filter: blur(22px) saturate(160%);
    padding:0;
    display:grid;
    grid-template-columns: minmax(0,1.1fr) minmax(0,0.9fr);
    overflow:hidden;
    position:relative;

    opacity:0;
    transform: translateY(30px) scale(.96);
    animation: shellIn .7s cubic-bezier(.22,.9,.31,1) .05s forwards;
    transition: transform .3s ease, box-shadow .3s ease;
}
.auth-shell:hover{
    transform: translateY(-4px) scale(1.01);
    box-shadow:0 40px 110px rgba(15,23,42,0.95);
}

/* đường chia giữa 2 cột */
.auth-shell::before{
    content:"";
    position:absolute;
    top:16px;
    bottom:16px;
    left:50%;
    width:1px;
    background:linear-gradient(to bottom, transparent, rgba(148,163,184,0.5), transparent);
    pointer-events:none;
}

/* LEFT: INTRO */
.auth-left{
    padding:28px 32px 26px;
    color:#f9fafb;
    background:radial-gradient(circle at top left, rgba(148,163,184,0.45), transparent 55%);
    position:relative;
    overflow:hidden;

    opacity:0;
    animation:leftIn .6s ease-out .15s forwards;
}
/* lớp mây phía sau nội dung bên trái */
.auth-left::before{
    content:"";
    position:absolute;
    inset:-40px;
    background:url('images/anenmb.png') center/cover no-repeat;
    opacity:0.45;
    mix-blend-mode:screen;
    filter:blur(1px);
    transform:scale(1.08) translate3d(0,0,0);
    transition:
        transform 6s ease-out,
        opacity .4s ease-out;
    z-index:-1; /* nằm dưới nội dung */
}

/* hover: mây dịch chuyển rất nhẹ */
.auth-left:hover::before{
    transform:scale(1.14) translate3d(-18px,-8px,0);
    opacity:0.55;
}


.left-logo{
    display:inline-flex;
    align-items:center;
    gap:8px;
    padding:6px 12px;
    border-radius:999px;
    border:1px solid rgba(255,255,255,0.55);
    font-size:11px;
    letter-spacing:.16em;
    text-transform:uppercase;
    background:rgba(15,23,42,0.4);
}
.left-logo i{color:var(--blue);}
.left-title{
    margin-top:18px;
    font-size:28px;
    font-weight:600;
}
.left-sub{
    margin-top:8px;
    font-size:14px;
    color:#e5e7eb;
    max-width:340px;
}
.left-badges{
    display:flex;
    flex-wrap:wrap;
    gap:10px;
    margin-top:18px;
}
.left-badge{
    padding:6px 10px;
    border-radius:999px;
    background:rgba(15,23,42,0.55);
    border:1px solid rgba(148,163,184,0.9);
    font-size:11px;
    display:flex;
    align-items:center;
    gap:6px;
}
.left-badge i{font-size:12px;}

/* RIGHT: FORM */
.auth-right{
    padding:26px 30px 24px;
    color:var(--text-main);

    opacity:0;
    animation:rightIn .6s ease-out .22s forwards;
}

/* Header right */
.brand{
    text-align:center;
}
.brand .logo{
    font-size:11px;
    letter-spacing:.18em;
    text-transform:uppercase;
    color:var(--blue);
}
.brand .title{
    font-size:22px;
    font-weight:600;
    margin-top:4px;
}

/* Tabs */
.tabs{
    display:flex;
    justify-content:center;
    gap:12px;
    margin:16px 0 6px;
}
.tabs button{
    padding:6px 18px;
    border-radius:999px;
    border:none;
    background:rgba(255,255,255,0.2);
    cursor:pointer;
    font-size:13px;
    color:var(--text-muted);
    transition:all .22s ease;
}
.tabs button.active{
    color:#fff;
    background:linear-gradient(135deg,var(--primary),var(--primary-soft));
    box-shadow:0 10px 24px rgba(239,41,71,0.6);
    transform:translateY(-1px);
}

/* Panel wrap tự co giãn */
.panel-wrap{
    position:relative;
    margin-top:16px;
    overflow:hidden;
    transition:height .28s ease;
}

/* Panel */
.panel{
    opacity:0;
    transform:translateY(8px);
    pointer-events:none;
    display:none;
}
.panel.active{
    display:block;
    pointer-events:auto;
    opacity:1;
    transform:translateY(0);
    animation:panelIn .28s ease-out;
}

/* Form control */
.form-control{
    width:100%;
    border:none;
    border-bottom:1px solid rgba(148,163,184,0.9);
    background:transparent;
    padding:9px 4px;
    margin-bottom:16px;
    font-size:14px;
    color:#0b1a2b;
    font-weight:500;
}
.form-control::placeholder{
    color:#0b1a2b;
    font-weight:500;
}
.form-control:focus{
    outline:none;
    border-bottom-color:var(--primary);
    box-shadow:0 2px 0 0 rgba(239,41,71,0.7);
}

/* Button */
.btn{
    width:100%;
    padding:11px;
    border-radius:999px;
    border:none;
    cursor:pointer;
    background:linear-gradient(135deg,var(--primary),var(--primary-soft));
    color:#fff;
    font-weight:500;
    margin-top:8px;
    box-shadow:0 18px 42px rgba(239,41,71,0.85);
    transition:transform .15s ease, box-shadow .15s ease, filter .15s ease;
}
.btn:hover{
    transform:translateY(-1px);
    filter:brightness(1.04);
    box-shadow:0 24px 56px rgba(239,41,71,1);
}
.btn:active{
    transform:translateY(0);
    box-shadow:0 12px 32px rgba(185,28,28,0.95);
}

/* Small text & links */
.small{
    text-align:center;
    margin-top:10px;
    font-size:13px;
    color:var(--text-muted);
}
.link{
    color:var(--primary);
    cursor:pointer;
}

/* Alert */
.alert{
    padding:8px 10px;
    border-radius:10px;
    font-size:13px;
    margin-bottom:10px;
}
.alert-danger{
    background:#fef2f2;
    border:1px solid #fecaca;
    color:#b91c1c;
}
.alert-success{
    background:#ecfdf5;
    border:1px solid #bbf7d0;
    color:#166534;
}

/* Responsive */
@media (max-width: 900px){
    .auth-shell{
        max-width:95%;
        grid-template-columns:1fr;
    }
    .auth-shell::before{
        display:none;
    }
    .auth-left{
        border-bottom:1px solid rgba(255,255,255,0.35);
    }
}
/* Link logo bên trái – bỏ gạch chân, giữ màu */
.auth-left a,
.auth-left a:visited {
    text-decoration: none;
    color: inherit;
}

.auth-left a:hover,
.auth-left a:focus {
    text-decoration: none;
    color: inherit; /* hoặc đặt màu bạn muốn */
}

</style>
</head>

<body>

<div class="auth-shell">

    <!-- LEFT INTRO -->
    <div class="auth-left">
        <a href="home.php">
        <div class="left-logo">
            <i class="fas fa-plane-departure"></i>
            <span>WL AIRLINE</span>
        </a>
        </div>
        <div class="left-title">Khám phá bầu trời cùng WL Airline</div>
        <div class="left-sub">
            Chỉ một tài khoản để quản lý đặt vé, hành khách và lịch sử chuyến bay của bạn, mọi lúc mọi nơi.
        </div>
        <div class="left-badges">
            <div class="left-badge">
                <i class="fas fa-shield-alt"></i> Bảo mật tài khoản
            </div>
            <div class="left-badge">
                <i class="fas fa-bolt"></i> Thanh toán nhanh chóng
            </div>
            <div class="left-badge">
                <i class="fas fa-globe-asia"></i> Hơn 150+ chặng bay
            </div>
        </div>
    </div>

    <!-- RIGHT AUTH -->
    <div class="auth-right">

        <div class="brand">
            <div class="logo">✈ WL AIRLINE</div>
            <div class="title">Chào mừng trở lại</div>
        </div>

        <div class="tabs">
            <button data-tab="login"    class="<?= $activeTab==='login'?'active':'' ?>">Đăng nhập</button>
            <button data-tab="register" class="<?= $activeTab==='register'?'active':'' ?>">Đăng ký</button>
            <button data-tab="forgot"   class="<?= $activeTab==='forgot'?'active':'' ?>">Quên mật khẩu</button>
        </div>

        <div class="panel-wrap">

            <!-- LOGIN -->
            <div id="login" class="panel <?= $activeTab==='login'?'active':'' ?>">
                <?php if($login_error): ?>
                    <div class="alert alert-danger"><?= $login_error ?></div>
                <?php endif; ?>

                <form method="POST">
                    <input type="hidden" name="form_type" value="login">
                    <input class="form-control" name="login_input" placeholder="Tên đăng nhập hoặc Email" required>
                    <input class="form-control" type="password" name="password" placeholder="Mật khẩu" required>
                    <button class="btn">Đăng nhập</button>

                    <div class="small">
                        <span class="link" data-link="forgot">Quên mật khẩu?</span><br>
                        Chưa có tài khoản?
                        <span class="link" data-link="register">Đăng ký ngay</span>
                    </div>
                </form>
            </div>

            <!-- REGISTER -->
            <div id="register" class="panel <?= $activeTab==='register'?'active':'' ?>">
                <?php if($reg_error): ?>
                    <div class="alert alert-danger"><?= $reg_error ?></div>
                <?php endif; ?>

                <form method="POST">
                    <input type="hidden" name="form_type" value="register">
                    <input class="form-control" name="hoten" placeholder="Họ và tên" required>
                    <input class="form-control" type="email" name="email" placeholder="Email" required>
                    <input class="form-control" name="sdt" placeholder="Số điện thoại" required>
                    <input class="form-control" name="ten_dang_nhap" placeholder="Tên đăng nhập" required>
                    <input class="form-control" type="password" name="mat_khau" placeholder="Mật khẩu" required>
                    <input class="form-control" name="so_cccd" placeholder="CCCD / Hộ chiếu" required>
                    <input class="form-control" type="date" name="ngaysinh" required>

                    <button class="btn">Tạo tài khoản</button>

                    <div class="small">
                        Đã có tài khoản?
                        <span class="link" data-link="login">Đăng nhập</span>
                    </div>
                </form>
            </div>

            <!-- FORGOT -->
            <div id="forgot" class="panel <?= $activeTab==='forgot'?'active':'' ?>">
                <?php if($msg): ?>
                    <div class="alert alert-<?= htmlspecialchars($msgType) ?>"><?= $msg ?></div>
                <?php endif; ?>

                <?php if($step==1): ?>
                    <form method="POST">
                        <input type="hidden" name="action" value="send_otp">
                        <input class="form-control" type="email" name="email" placeholder="Email đã đăng ký" required>
                        <button class="btn">Gửi OTP</button>
                    </form>

                <?php elseif($step==2): ?>
                    <form method="POST">
                        <input type="hidden" name="action" value="verify_otp">
                        <input class="form-control" name="otp" placeholder="Nhập mã OTP" required>
                        <button class="btn">Xác thực</button>
                    </form>

                <?php elseif($step==3): ?>
                    <form method="POST">
                        <input type="hidden" name="action" value="reset_pass">
                        <input class="form-control" type="password" name="new_pass" placeholder="Mật khẩu mới" required>
                        <input class="form-control" type="password" name="confirm_pass" placeholder="Nhập lại mật khẩu" required>
                        <button class="btn">Cập nhật mật khẩu</button>
                    </form>

                <?php else: ?>
                    <div class="small" style="color:#166534">
                        Mật khẩu đã được đổi thành công. Bạn có thể đăng nhập lại.
                    </div>
                <?php endif; ?>

                <div class="small" style="margin-top:12px;">
                    <span class="link" data-link="login">Quay lại đăng nhập</span>
                </div>
            </div>

        </div>
    </div>
</div>

<script>
// Tabs + panel + auto height cho cột bên phải
const tabBtns = document.querySelectorAll(".tabs button");
const panels  = document.querySelectorAll(".panel");
const links   = document.querySelectorAll("[data-link]");
const wrap    = document.querySelector(".panel-wrap");

function setHeight(){
    const active = document.querySelector(".panel.active");
    if (!active || !wrap) return;
    wrap.style.height = active.scrollHeight + "px";
}

function showTab(name){
    panels.forEach(p => p.classList.toggle("active", p.id === name));
    tabBtns.forEach(b => b.classList.toggle("active", b.dataset.tab === name));
    setHeight();
}

tabBtns.forEach(b => b.addEventListener("click", () => showTab(b.dataset.tab)));
links.forEach(l => l.addEventListener("click", () => showTab(l.dataset.link)));

window.addEventListener("load", setHeight);
</script>

</body>
</html>

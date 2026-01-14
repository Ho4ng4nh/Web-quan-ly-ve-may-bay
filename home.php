<?php
require_once 'db.php';
$isLoggedIn = isset($_SESSION['MaKH']);
$userName = $isLoggedIn ? $_SESSION['HoTen'] : '';
$danhSachSanBay = [];
$danhSachHang = [];
$dsChuyenBayHot = [];

try {
    $stmt = $conn->prepare("SELECT MaSanBay, TenSanBay, DiaChi FROM SanBay");
    $stmt->execute();
    $danhSachSanBay = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $stmtHang = $conn->prepare("SELECT MaHang, TenHang FROM HangHK");
    $stmtHang->execute();
    $danhSachHang = $stmtHang->fetchAll(PDO::FETCH_ASSOC);

    $sqlHot = "SELECT 
                    cb.MaCB, 
                    sb.DiaChi AS DiemDen, 
                    sb.TenSanBay, 
                    MIN(g.Gia) AS GiaThapNhat,
                    (SELECT DuongDan FROM HinhAnhChuyenBay ha WHERE ha.MaCB = cb.MaCB LIMIT 1) AS HinhAnh
               FROM ChuyenBay cb
               JOIN SanBay sb ON cb.MaSanBayDen = sb.MaSanBay
               JOIN Ghe g ON cb.MaCB = g.MaCB
               WHERE cb.Thoigiankhoihanh > NOW()
               GROUP BY cb.MaCB
               ORDER BY GiaThapNhat ASC
               LIMIT 6";
    $stmtHot = $conn->prepare($sqlHot);
    $stmtHot->execute();
    $dsChuyenBayHot = $stmtHot->fetchAll(PDO::FETCH_ASSOC);

} catch (PDOException $e) {
    error_log("Lỗi DB: " . $e->getMessage());
}
?>
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WL Airline - Trang Chủ</title>

    <!-- BOOTSTRAP & ICONS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Be+Vietnam+Pro:wght@300;400;500;600;700;800&display=swap&subset=vietnamese" rel="stylesheet">


    <style>
        :root {
            --red-primary: #E60023;
            --red-soft: #ff4b5c;
            --navy: #001b3a;
            --navy-soft: #012749;
            --bg-body: #f5f7fb;
            --text-dark: #121826;
            --light: #ffffff;
            --badge-gold: #ffc947;
        }

        * {
            box-sizing: border-box;
        }

        body {
            font-family: 'Be Vietnam Pro', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: radial-gradient(circle at top left, #fef2f2 0, #f5f7fb 40%, #e9f0ff 100%);
    color: var(--text-dark);
        }

        /* ================= NAVBAR ================= */

        .navbar {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(18px);
            box-shadow: 0 12px 40px rgba(0,0,0,0.08);
            padding: 8px 0;
            z-index: 1000;
        }

        .navbar-brand {
            font-weight: 800;
            letter-spacing: 1px;
            color: var(--navy) !important;
            text-transform: uppercase;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .navbar-brand i {
            color: var(--red-primary);
            font-size: 1.4rem;
        }

        .nav-slider-container {
            position: relative;
            display: flex;
            align-items: center;
            background: #eef1f7;
            padding: 4px;
            border-radius: 999px;
            gap: 4px;
        }

        .nav-item-custom {
            position: relative;
            z-index: 2;
            list-style: none;
        }

        .nav-link-custom {
            display: block;
            color: #4b5563;
            font-weight: 600;
            text-decoration: none;
            padding: 8px 20px;
            min-width: 120px;
            text-align: center;
            font-size: 0.95rem;
            border-radius: 999px;
            transition: color 0.3s ease, transform 0.2s ease;
        }

        .nav-item-custom.active .nav-link-custom {
            color: #ffffff !important;
        }

        .nav-item-custom:hover .nav-link-custom {
            transform: translateY(-1px);
        }

        .nav-slider {
            position: absolute;
            top: 4px;
            left: 4px;
            height: calc(100% - 8px);
            background: linear-gradient(135deg, var(--red-primary), var(--red-soft));
            border-radius: 999px;
            transition: all 0.35s cubic-bezier(0.77, 0, 0.175, 1);
            z-index: 1;
            opacity: 0;
            box-shadow: 0 10px 26px rgba(230,0,35,0.4);
        }

        .btn-login {
            background: linear-gradient(135deg, var(--red-primary), var(--red-soft));
            color: #ffffff !important;
            border-radius: 999px;
            padding: 8px 26px;
            font-weight: 600;
            border: none;
            box-shadow: 0 10px 22px rgba(230,0,35,0.3);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 16px 30px rgba(230,0,35,0.5);
        }

        /* ================= HERO ================= */

        .hero-section {
            position: relative;
            height: 100vh;          /* giới hạn đúng 1 màn hình */
            padding-top: 90px;
            display: flex;
            align-items: center;
            overflow: hidden;
            z-index: 1;
        }

        /* carousel không nhận sự kiện chuột */
        #heroCarousel {
            position: absolute;
            inset: 0;
            z-index: 1;
            pointer-events: none !important;
        }

        .carousel-item {
            height: 100%;
            min-height: 100vh;
        }

        .carousel-item img {
            width: 100%;
            height: 100%;
            object-fit: cover;
            filter: saturate(1.15);
        }

        /* overlay cũng không nhận sự kiện */
        .hero-overlay {
            position: absolute;
            inset: 0;
            background: radial-gradient(circle at 20% 0%, rgba(230,0,35,0.75), transparent 55%),
                        linear-gradient(to bottom right, rgba(0,0,0,0.75), rgba(0,27,58,0.85));
            z-index: 2;
            mix-blend-mode: multiply;
            pointer-events: none !important;
        }

        .hero-content {
            position: relative;
            z-index: 3;
            color: #ffffff;
        }

        .hero-row {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 32px;
        }

        .hero-left {
            flex: 1 1 330px;
            max-width: 520px;
        }

        .hero-title {
            font-size: clamp(2.6rem, 4vw, 3.4rem);
            font-weight: 800;
            line-height: 1.1;
            margin-bottom: 16px;
            text-shadow: 0 10px 30px rgba(0,0,0,0.6);
        }

        .hero-highlight {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            padding: 6px 14px;
            background: rgba(255,255,255,0.1);
            border-radius: 999px;
            border: 1px solid rgba(255,255,255,0.25);
            font-size: 0.9rem;
            margin-bottom: 16px;
            backdrop-filter: blur(10px);
        }

        .hero-highlight span.badge-hot {
            background: linear-gradient(135deg, #ffc947, #ff8400);
            border-radius: 999px;
            padding: 4px 10px;
            font-weight: 700;
            color: #1f2933;
        }

        .hero-sub {
            font-size: 0.98rem;
            color: rgba(255,255,255,0.75);
            max-width: 420px;
            margin-bottom: 22px;
        }

        .hero-stats {
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            margin-top: 8px;
        }

        .hero-stat-box {
            background: rgba(3,7,18,0.6);
            border-radius: 16px;
            padding: 10px 16px;
            border: 1px solid rgba(148,163,184,0.6);
            min-width: 120px;
        }

        .hero-stat-box h4 {
            margin: 0;
            font-size: 1.2rem;
            font-weight: 700;
        }

        .hero-stat-box span {
            font-size: 0.78rem;
            color: rgba(226,232,240,0.8);
        }

        .hero-right {
            flex: 1 1 360px;
            max-width: 560px;
        }

        .search-box {
            background: radial-gradient(circle at top left, rgba(255,255,255,0.9), rgba(241,245,249,0.98));
            padding: 26px 26px 22px;
            border-radius: 24px;
            box-shadow: 0 20px 50px rgba(0,0,0,0.55);
            backdrop-filter: blur(14px);
            border: 1px solid rgba(248,250,252,0.75);
        }

        .search-title {
            font-size: 1rem;
            font-weight: 700;
            color: var(--navy);
            margin-bottom: 6px;
        }

        .search-sub {
            font-size: 0.8rem;
            color: #6b7280;
            margin-bottom: 14px;
        }

        .trip-type-toggle {
            display: inline-flex;
            border-radius: 999px;
            padding: 3px;
            background: #e5e7eb;
            margin-bottom: 10px;
            gap: 4px;
        }

        .trip-type-btn {
            border-radius: 999px;
            border: none;
            padding: 4px 10px;
            font-size: 0.8rem;
            background: transparent;
            color: #4b5563;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .trip-type-btn.active {
            background: #ffffff;
            color: var(--red-primary);
            box-shadow: 0 4px 10px rgba(148,163,184,0.5);
        }

        .form-label {
            color: #6b7280;
            font-size: 0.78rem;
            font-weight: 600;
            margin-bottom: 4px;
            display: block;
        }

        .form-label i {
            color: var(--red-primary);
        }

        .form-control,
        .form-select {
            border-radius: 12px;
            border: 1px solid #e5e7eb;
            background-color: #f9fafb;
            font-size: 0.9rem;
            padding: 8px 10px;
            transition: all 0.2s ease;
        }

        .form-control:focus,
        .form-select:focus {
            border-color: var(--red-primary);
            box-shadow: 0 0 0 1px rgba(230,0,35,0.25);
            background-color: #ffffff;
        }

        .btn-search {
            background: linear-gradient(135deg, var(--red-primary), var(--red-soft));
            color: #ffffff;
            border: none;
            border-radius: 18px;
            width: 100%;
            padding: 11px;
            font-weight: 700;
            font-size: 1rem;
            letter-spacing: 0.03em;
            box-shadow: 0 16px 36px rgba(230,0,35,0.45);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .btn-search:hover {
            transform: translateY(-1px) scale(1.01);
            box-shadow: 0 20px 50px rgba(230,0,35,0.65);
        }

        /* ============= SECTION CHUYẾN BAY HOT ============= */

        .section-wrapper {
            position: relative;
            padding: 72px 0 60px;
            z-index: 5; /* luôn nằm trên hero */
        }

        .section-wrapper::before {
            content: "";
            position: absolute;
            inset: 0;
            background: radial-gradient(circle at top, rgba(0,27,58,0.03), transparent 55%);
            pointer-events: none;
        }

        .section-header {
            position: relative;
            text-align: center;
            margin-bottom: 40px;
        }

        .section-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 4px 14px;
            border-radius: 999px;
            background: rgba(230,0,35,0.06);
            color: var(--red-primary);
            font-size: 0.78rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }

        .section-title {
            font-weight: 800;
            margin-top: 12px;
            font-size: 1.9rem;
            color: var(--navy);
        }

        .section-sub {
            max-width: 520px;
            margin: 8px auto 0;
            color: #6b7280;
            font-size: 0.9rem;
        }

        .destination-card {
            border: none;
            border-radius: 18px;
            overflow: hidden;
            background: #ffffff;
            box-shadow: 0 10px 25px rgba(15,23,42,0.08);
            transition: transform 0.25s ease, box-shadow 0.25s ease, border 0.25s ease;
            position: relative;
        }

        .destination-card::after {
            content: "";
            position: absolute;
            inset: 0;
            border-radius: inherit;
            border: 1px solid transparent;
            transition: border 0.25s ease;
        }

        .destination-card:hover {
            transform: translateY(-10px);
            box-shadow: 0 26px 45px rgba(15,23,42,0.25);
        }

        .destination-card:hover::after {
            border-color: rgba(230,0,35,0.45);
        }

        .card-img-top {
            height: 230px;
            object-fit: cover;
        }

        .card-body {
            padding: 18px 18px 16px;
        }

        .price-tag {
            color: var(--red-primary);
            font-weight: 800;
            font-size: 1.1rem;
        }

        .btn-pill-outline {
            border-radius: 999px;
            border: 1px solid var(--red-primary);
            color: var(--red-primary);
            font-size: 0.85rem;
            padding: 6px 16px;
            font-weight: 600;
            background: transparent;
            transition: all 0.2s ease;
        }

        .btn-pill-outline:hover {
            background: var(--red-primary);
            color: #ffffff;
            box-shadow: 0 10px 24px rgba(230,0,35,0.5);
        }

        .favorite-tag {
            position: absolute;
            top: 14px;
            left: 14px;
            background: rgba(0,27,58,0.78);
            color: #ffffff;
            font-size: 0.7rem;
            padding: 4px 10px;
            border-radius: 999px;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }

        .favorite-tag i {
            color: #ffc947;
        }

        /* ============= ƯU ĐIỂM ============= */

        .benefit-section {
            background: #ffffff;
            padding: 56px 0 50px;
            position: relative;
            z-index: 5;
        }

        .benefit-icon {
            width: 58px;
            height: 58px;
            border-radius: 18px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            background: radial-gradient(circle at top, rgba(230,0,35,0.15), rgba(0,27,58,0.95));
            color: #ffffff;
            margin-bottom: 14px;
            box-shadow: 0 12px 30px rgba(15,23,42,0.55);
        }

        .benefit-box h4 {
            font-weight: 700;
            color: var(--navy);
        }

        .benefit-box p {
            font-size: 0.9rem;
            color: #6b7280;
        }

        /* ============= FOOTER ============= */

        footer {
            background: radial-gradient(circle at top, #011327, #000814);
            color: #9ca3af;
            padding: 45px 0 18px;
            position: relative;
            z-index: 5;
        }

        footer h5 {
            color: #e5e7eb;
            font-weight: 700;
            margin-bottom: 16px;
        }

        footer a {
            color: #9ca3af;
            text-decoration: none;
            font-size: 0.9rem;
            transition: color 0.2s ease, transform 0.2s ease;
        }

        footer a:hover {
            color: #ffffff;
            transform: translateX(2px);
        }

        footer .brand-footer {
            font-weight: 700;
            letter-spacing: 1px;
            color: #ffffff;
        }

        /* ============= ANIMATION / REVEAL ============= */

        .reveal {
            opacity: 0;
            transform: translateY(24px);
            transition: opacity 0.6s ease, transform 0.6s ease;
        }
        .reveal.show {
            opacity: 1;
            transform: translateY(0);
        }

        @media (max-width: 991.98px) {
            .nav-slider-container {
                margin: 10px 0;
            }
            .hero-section {
                padding-top: 88px;
                padding-bottom: 40px;
            }
            .hero-row {
                flex-direction: column;
            }
            .search-box {
                margin-top: 10px;
            }
        }

        @media (max-width: 575.98px) {
            .hero-title {
                font-size: 2.1rem;
            }
            .hero-stats {
                gap: 10px;
            }
        }

        h2 {
            font-family: 'Times New Roman';
        }
        .destination-card::after {
    pointer-events: none !important;
}

    </style>
</head>
<body>
    <!-- NAVBAR -->
    <nav class="navbar navbar-expand-lg fixed-top">
        <div class="container">
            <a class="navbar-brand" href="home.php">
                <i class="fas fa-plane-departure"></i>
                WL AIRLINE
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            
            <div class="collapse navbar-collapse" id="navbarNav">
                <!-- TAB NAV CUSTOM -->
                <ul class="nav-slider-container mx-auto mb-2 mb-lg-0">
                    <li class="nav-item-custom active">
                        <a class="nav-link-custom" href="home.php">Trang chủ</a>
                    </li>
                    <li class="nav-item-custom">
                        <a class="nav-link-custom" href="flight.php">Vé máy bay</a>
                    </li>
                    <li class="nav-item-custom">
                        <a class="nav-link-custom" href="promotion.php">Khuyến mãi</a>
                    </li>
                    <li class="nav-item-custom">
                        <a class="nav-link-custom" href="contact.php">Liên hệ</a>
                    </li>
                    <div class="nav-slider"></div>
                </ul>

                <ul class="navbar-nav ms-auto align-items-center">
                    <?php if ($isLoggedIn): ?>
                        <li class="nav-item dropdown ms-3">
                            <a class="nav-link dropdown-toggle fw-bold text-dark" href="#" role="button" data-bs-toggle="dropdown">
                                <i class="fa-regular fa-circle-user me-1 text-danger"></i>
                                Xin chào, <?= htmlspecialchars($userName) ?>
                            </a>
                            <ul class="dropdown-menu dropdown-menu-end border-0 shadow">
                                <li><a class="dropdown-item" href="profile.php"><i class="fa-regular fa-user me-2"></i>Thông tin cá nhân</a></li>
                                <li><a class="dropdown-item" href="booking_history.php"><i class="fas fa-history me-2"></i>Lịch sử đặt vé</a></li>
                                <li><a class="dropdown-item text-danger" href="logout.php"><i class="fas fa-sign-out-alt me-2"></i>Đăng xuất</a></li>
                            </ul>
                        </li>
                    <?php else: ?>
                        <li class="nav-item ms-3">
                            <a class="btn btn-login shadow-sm" href="login.php">
                                <i class="fa-regular fa-circle-user me-1"></i>
                                Đăng nhập / Đăng ký
                            </a>
                        </li>
                    <?php endif; ?>
                </ul>
            </div>
        </div>
    </nav>

    <!-- HERO -->
    <section class="hero-section">
        <div id="heroCarousel" class="carousel slide carousel-fade" data-bs-ride="carousel" data-bs-interval="4500">
            <div class="carousel-inner">
                <div class="carousel-item active">
                    <img src="https://images.unsplash.com/photo-1436491865332-7a61a109cc05?q=80&w=2074" alt="Slide 1">
                </div>
                <div class="carousel-item">
                    <img src="https://images.unsplash.com/photo-1569154941061-e231b4725ef1?q=80&w=2070" alt="Slide 2">
                </div>
                <div class="carousel-item">
                    <img src="https://images.unsplash.com/photo-1542296332-2e4473faf563?q=80&w=2070" alt="Slide 3">
                </div>
            </div>
        </div>
        <div class="hero-overlay"></div>

        <div class="container hero-content">
            <div class="hero-row">
                <!-- LEFT TEXT -->
                <div class="hero-left reveal">
                    <div class="hero-highlight">
                        <span class="badge-hot">HOT DEAL</span>
                        <span>Ưu đãi vé bay từ 199.000đ • Số lượng có hạn</span>
                    </div>
                    <h1 class="hero-title">Khám phá thế giới<br>cùng <span style="color:#ffc947;">WL Airline</span></h1>
                    <p class="hero-sub">
                        Kết nối mọi hành trình của bạn với những chuyến bay an toàn, đẳng cấp
                        và linh hoạt. Chọn điểm đến, việc còn lại để WL Airline lo.
                    </p>
                    <div class="hero-stats">
                        <div class="hero-stat-box">
                            <h4>150+</h4>
                            <span>Đường bay nội địa & quốc tế</span>
                        </div>
                        <div class="hero-stat-box">
                            <h4>4.8⭐</h4>
                            <span>Đánh giá trải nghiệm của khách hàng</span>
                        </div>
                    </div>
                </div>

                <!-- RIGHT SEARCH BOX -->
                <div class="hero-right reveal">
                    <div class="search-box">
                        <div class="d-flex justify-content-between align-items-center mb-1">
                            <div>
                                <div class="search-title">Tìm chuyến bay phù hợp</div>
                                <div class="search-sub">So sánh giá vé theo hãng, giờ bay và điểm đến.</div>
                            </div>
                            <i class="fas fa-ticket-alt text-danger fs-4"></i>
                        </div>

                        <div class="trip-type-toggle">
                            <button type="button" class="trip-type-btn active">Khứ hồi</button>
                            <button type="button" class="trip-type-btn">Một chiều</button>
                        </div>

                        <form action="search.php" method="GET">
                            <div class="row g-3 mb-2">
                                <div class="col-md-6">
                                    <label class="form-label">
                                        <i class="fas fa-plane-departure me-1"></i>Điểm đi
                                    </label>
                                    <select name="diem_di" class="form-select">
                                        <option selected value="">Tất cả điểm đi</option>
                                        <?php foreach ($danhSachSanBay as $sb): ?>
                                            <option value="<?= $sb['MaSanBay'] ?>"><?= htmlspecialchars($sb['TenSanBay']) ?></option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label">
                                        <i class="fas fa-plane-arrival me-1"></i>Điểm đến
                                    </label>
                                    <select name="diem_den" class="form-select">
                                        <option selected value="">Tất cả điểm đến</option>
                                        <?php foreach ($danhSachSanBay as $sb): ?>
                                            <option value="<?= $sb['MaSanBay'] ?>"><?= htmlspecialchars($sb['TenSanBay']) ?></option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                            </div>

                            <div class="row g-3 mb-2">
                                <div class="col-md-6">
                                    <label class="form-label">
                                        <i class="far fa-calendar-alt me-1"></i>Ngày đi
                                    </label>
                                    <input type="date" name="ngay_di" class="form-control">
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label">
                                        <i class="far fa-calendar-check me-1"></i>Ngày về
                                    </label>
                                    <input type="date" name="ngay_ve" class="form-control" placeholder="Chọn ngày về">
                                </div>
                            </div>

                            <div class="row g-3 align-items-end">
                                <div class="col-md-8">
                                    <label class="form-label">
                                        <i class="fas fa-flag me-1"></i>Hãng hàng không
                                    </label>
                                    <select name="hang_hk" class="form-select">
                                        <option selected value="">Tất cả các hãng</option>
                                        <?php foreach ($danhSachHang as $h): ?>
                                            <option value="<?= $h['MaHang'] ?>"><?= htmlspecialchars($h['TenHang']) ?></option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                                <div class="col-md-4">
                                    <button type="submit" class="btn btn-search mt-2 mt-md-4">
                                        <i class="fas fa-search me-2"></i>TÌM KIẾM
                                    </button>
                                </div>
                            </div>
                        </form>

                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- CHUYẾN BAY HOT -->
    <section class="section-wrapper">
        <div class="container reveal">
            <div class="section-header">
                <div class="section-badge">
                    <i class="fas fa-fire"></i> Ưu đãi nổi bật
                </div>
                <h2 class="section-title">Chuyến bay hot nhất hôm nay</h2>
                <p class="section-sub">
                    Lựa chọn nhanh các điểm đến được yêu thích, giá tốt nhất hiện tại. Đặt sớm để giữ chỗ!
                </p>
            </div>

            <div class="row g-4">
                <?php if (count($dsChuyenBayHot) > 0): ?>
                    <?php foreach ($dsChuyenBayHot as $hotFlight): ?>
                        <div class="col-md-4">
                            <div class="card destination-card h-100">
                                <?php 
                                    $imgSrc = 'https://via.placeholder.com/400x250?text=No+Image';
                                    if (!empty($hotFlight['HinhAnh'])) {
                                        if (filter_var($hotFlight['HinhAnh'], FILTER_VALIDATE_URL)) {
                                            $imgSrc = $hotFlight['HinhAnh']; 
                                        } else {
                                            $imgSrc = 'uploads/flights/' . $hotFlight['HinhAnh']; 
                                        }
                                    }
                                ?>
                                <span class="favorite-tag">
                                    <i class="fas fa-crown"></i> Top pick
                                </span>
                                <img src="<?= htmlspecialchars($imgSrc) ?>" class="card-img-top" alt="<?= htmlspecialchars($hotFlight['DiemDen']) ?>">
                                
                                <div class="card-body d-flex flex-column">
                                    <h5 class="card-title fw-bold mb-1">
                                        <?= htmlspecialchars($hotFlight['DiemDen']) ?>
                                    </h5>
                                    <p class="card-text text-muted mb-2">
                                        Sân bay: <strong><?= htmlspecialchars($hotFlight['TenSanBay']) ?></strong><br>
                                        <small>Trải nghiệm hành trình tuyệt vời với nhiều khung giờ linh hoạt.</small>
                                    </p>
                                    <div class="mt-auto d-flex justify-content-between align-items-center">
                                        <span class="price-tag">
                                            <?= number_format($hotFlight['GiaThapNhat'], 0, ',', '.') ?> VNĐ
                                        </span>
                                        <a href="select_seat.php?macb=<?= $hotFlight['MaCB'] ?>" class="btn btn-pill-outline">
                                            Đặt ngay
                                        </a>
                                    </div>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php else: ?>
                    <div class="text-center">
                        <p class="text-muted">Hiện tại chưa có ưu đãi nào được cập nhật.</p>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </section>

    <!-- ƯU ĐIỂM -->
    <section class="benefit-section">
        <div class="container">
            <div class="row text-center g-4">
                <div class="col-md-4 reveal">
                    <div class="benefit-box p-3">
                        <div class="benefit-icon">
                            <i class="fas fa-shield-alt fa-lg"></i>
                        </div>
                        <h4 class="fw-bold">An toàn tuyệt đối</h4>
                        <p>Đội ngũ phi công, tiếp viên và kỹ thuật được đào tạo bài bản, tuân thủ tiêu chuẩn quốc tế.</p>
                    </div>
                </div>
                <div class="col-md-4 reveal">
                    <div class="benefit-box p-3">
                        <div class="benefit-icon">
                            <i class="fas fa-tag fa-lg"></i>
                        </div>
                        <h4 class="fw-bold">Giá vé cạnh tranh</h4>
                        <p>Theo dõi giá liên tục, thường xuyên tung ra các chương trình khuyến mãi cực kỳ hấp dẫn.</p>
                    </div>
                </div>
                <div class="col-md-4 reveal">
                    <div class="benefit-box p-3">
                        <div class="benefit-icon">
                            <i class="fas fa-headset fa-lg"></i>
                        </div>
                        <h4 class="fw-bold">Hỗ trợ 24/7</h4>
                        <p>Đội ngũ chăm sóc khách hàng luôn sẵn sàng giải đáp mọi thắc mắc của bạn mọi lúc, mọi nơi.</p>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- FOOTER -->
    <footer>
        <div class="container">
            <div class="row">
                <div class="col-md-4 mb-4">
                    <div class="brand-footer mb-2">WL AIRLINE</div>
                    <p>Hãng hàng không với sứ mệnh kết nối mọi miền tổ quốc, mang đến trải nghiệm bay an toàn và tiện nghi.</p>
                </div>
                <div class="col-md-2 mb-4">
                    <h5>Về chúng tôi</h5>
                    <ul class="list-unstyled">
                        <li><a href="index.php">Giới thiệu</a></li>
                        <li><a href="index.php">Tuyển dụng</a></li>
                    </ul>
                </div>
                <div class="col-md-2 mb-4">
                    <h5>Hỗ trợ</h5>
                    <ul class="list-unstyled">
                        <li><a href="#">Trung tâm trợ giúp</a></li>
                        <li><a href="#">Hoàn đổi vé</a></li>
                    </ul>
                </div>
                <div class="col-md-4 mb-4">
                    <h5>Liên hệ</h5>
                    <p><i class="fas fa-map-marker-alt me-2"></i> 123 Đường Bay, Hà Nội</p>
                    <p><i class="fas fa-phone me-2"></i> 1900 1234</p>
                </div>
            </div>
            <div class="border-top border-secondary pt-3 text-center">
                <p class="mb-0">&copy; 2025 WL Airline. All rights reserved.</p>
            </div>
        </div>
    </footer>

    <!-- SCRIPT -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>

    <script>
        // NAV TAB SLIDER HIỆU ỨNG
        document.addEventListener("DOMContentLoaded", function() {
            const navContainer = document.querySelector('.nav-slider-container');
            const slider = document.querySelector('.nav-slider');
            const items = document.querySelectorAll('.nav-item-custom');

            function moveSlider(targetItem) {
                if (!targetItem) {
                    slider.style.opacity = '0';
                    return;
                }
                const link = targetItem.querySelector('.nav-link-custom');
                const rect = link.getBoundingClientRect();
                const parentRect = navContainer.getBoundingClientRect();

                slider.style.width = rect.width + 'px';
                slider.style.left = (rect.left - parentRect.left) + 'px';
                slider.style.opacity = '1';
            }

            // Xác định active theo URL
            const currentPath = window.location.pathname.split('/').pop();
            items.forEach(item => {
                const link = item.querySelector('.nav-link-custom');
                const href = link.getAttribute('href');
                if (href === currentPath || (currentPath === '' && href === 'home.php')) {
                    items.forEach(i => i.classList.remove('active'));
                    item.classList.add('active');
                }
            });

            const activeItem = document.querySelector('.nav-item-custom.active');
            moveSlider(activeItem);

            items.forEach(item => {
                item.addEventListener('mouseenter', function() {
                    moveSlider(this);
                });
                item.addEventListener('click', function() {
                    items.forEach(i => i.classList.remove('active'));
                    this.classList.add('active');
                    moveSlider(this);
                });
            });

            navContainer.addEventListener('mouseleave', function() {
                const act = document.querySelector('.nav-item-custom.active');
                moveSlider(act);
            });
        });

        // NÚT KHỨ HỒI / MỘT CHIỀU (hiệu ứng UI)
        document.querySelectorAll('.trip-type-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                document.querySelectorAll('.trip-type-btn').forEach(b => b.classList.remove('active'));
                this.classList.add('active');
            });
        });

        // SCROLL REVEAL
        const revealElements = document.querySelectorAll('.reveal');

        function handleReveal() {
            const triggerBottom = window.innerHeight * 0.86;
            revealElements.forEach(el => {
                const rect = el.getBoundingClientRect();
                if (rect.top < triggerBottom) {
                    el.classList.add('show');
                }
            });
        }

        window.addEventListener('scroll', handleReveal);
        window.addEventListener('load', handleReveal);
    </script>
</body>
</html>

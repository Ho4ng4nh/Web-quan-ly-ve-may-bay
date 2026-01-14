<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WL Airline - Cinematic Intro</title>

    <!-- Bootstrap (nếu sau này cần) -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@300;400;500;600;700;900&display=swap" rel="stylesheet">
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <!-- AOS -->
    <link href="https://unpkg.com/aos@2.3.1/dist/aos.css" rel="stylesheet">

    <style>
        :root {
            --red: #e50914;
            --red-soft: #ff3b4c;
            --bg-dark: #020308;
            --glass-bg: rgba(255, 255, 255, 0.06);
            --border-soft: rgba(255, 255, 255, 0.25);
            --text-muted: rgba(255, 255, 255, 0.75);
        }

        * {
            box-sizing: border-box;
        }

        html, body {
            margin: 0;
            padding: 0;
            font-family: 'Montserrat', sans-serif;
            background: var(--bg-dark);
            color: #fff;
            overflow-x: hidden;
        }

        /* ================== GLOBAL BACKGROUND ================== */
        .bg-intro {
            position: fixed;
            inset: 0;
            background:
                radial-gradient(circle at 10% 0%, rgba(229,9,20,0.18), transparent 60%),
                radial-gradient(circle at 80% 80%, rgba(0,0,0,0.9), transparent 60%),
                url('https://images.unsplash.com/photo-1542296332-2e4473faf563?auto=format&fit=crop&w=2070&q=80')
                    center center / cover no-repeat fixed;
            filter: brightness(30%) contrast(120%);
            animation: bgZoom 26s ease-in-out infinite alternate;
            z-index: 1;
        }

        @keyframes bgZoom {
            0%   { transform: scale(1) translateY(0); }
            100% { transform: scale(1.13) translateY(-10px); }
        }

        .noise-overlay {
            pointer-events: none;
            position: fixed;
            inset: 0;
            z-index: 2;
            background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 160 160' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='1.2' numOctaves='4' stitchTiles='noStitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.08'/%3E%3C/svg%3E");
            mix-blend-mode: soft-light;
        }

        .red-overlay {
            position: fixed;
            inset: 0;
            background:
                radial-gradient(circle at 50% 70%, rgba(229,9,20,0.55), transparent 55%),
                linear-gradient(to bottom, rgba(0,0,0,0.2), rgba(0,0,0,0.92));
            z-index: 3;
        }

        .particles {
            position: fixed;
            inset: 0;
            pointer-events: none;
            z-index: 4;
        }

        .particle {
            position: absolute;
            width: 3px;
            height: 3px;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.9);
            filter: blur(1px);
            opacity: 0;
            animation: floatUp 7s linear infinite;
        }

        @keyframes floatUp {
            0%   { opacity: 0; transform: translateY(30px); }
            25%  { opacity: 0.9; }
            75%  { opacity: 0.7; }
            100% { opacity: 0; transform: translateY(-150px); }
        }

        /* ================== NAVBAR ================== */
        .navbar-glass {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            z-index: 10;
            background: linear-gradient(to bottom, rgba(0,0,0,0.9), transparent);
            padding: 16px 40px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            backdrop-filter: blur(14px);
        }

        .brand-mini {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .brand-mini-logo {
            width: 38px;
            height: 38px;
            border-radius: 999px;
            background: #f5f5f5;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 0 18px rgba(229,9,20,0.7);
        }

        .brand-mini-logo i {
            color: var(--red);
            font-size: 1.2rem;
        }

        .brand-mini-text {
            font-weight: 800;
            letter-spacing: 2px;
            text-transform: uppercase;
            font-size: 1rem;
        }

        .brand-mini-text span {
            color: var(--red);
        }

        .nav-actions {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .btn-nav {
            border-radius: 999px;
            border: 1px solid rgba(255,255,255,0.35);
            padding: 7px 16px;
            font-size: 0.8rem;
            letter-spacing: 0.5px;
            background: rgba(0,0,0,0.4);
            color: #fff;
            text-decoration: none;
            transition: 0.25s;
        }

        .btn-nav:hover {
            background: rgba(255,255,255,0.1);
        }

        .btn-nav-primary {
            border-color: transparent;
            background: linear-gradient(130deg, var(--red), var(--red-soft));
            box-shadow: 0 0 18px rgba(229,9,20,0.7);
        }

        .btn-nav-primary:hover {
            transform: translateY(-1px) scale(1.02);
            box-shadow: 0 0 24px rgba(229,9,20,0.9);
        }

        /* ================== HERO ================== */
        .hero-wrapper {
            position: relative;
            z-index: 5;
            min-height: 100vh;
            display: flex;
            align-items: center;
            padding: 90px 4vw 40px;
        }

        .hero-inner {
            width: 100%;
            max-width: 1240px;
            margin: 0 auto;
            display: grid;
            grid-template-columns: minmax(0, 1.25fr) minmax(0, 1fr);
            gap: 40px;
            align-items: center;
        }

        /* Hero logo */
        .hero-logo {
            display: inline-flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 14px;
        }

        .hero-logo-icon {
            width: 52px;
            height: 52px;
            border-radius: 18px;
            background: #f9f9f9;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 0 24px rgba(229,9,20,0.8);
        }

        .hero-logo-icon i {
            color: var(--red);
            font-size: 1.6rem;
        }

        .hero-logo-text {
            font-weight: 800;
            letter-spacing: 3px;
            text-transform: uppercase;
            font-size: 1.1rem;
        }

        .hero-logo-text span {
            color: var(--red);
        }

        .hero-tagline {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 4px 10px;
            border-radius: 999px;
            background: rgba(0,0,0,0.6);
            border: 1px solid rgba(255,255,255,0.2);
            font-size: 0.8rem;
            letter-spacing: 1px;
            text-transform: uppercase;
            color: var(--text-muted);
            margin-bottom: 12px;
        }

        .hero-tagline i {
            color: var(--red);
        }

        .brand-title {
            font-size: clamp(3.4rem, 5vw + 1rem, 5.4rem);
            font-weight: 900;
            text-transform: uppercase;
            letter-spacing: 4px;
            line-height: 1.02;
            margin-bottom: 10px;
        }

        .brand-title span {
            background: linear-gradient(90deg, var(--red), #ff9a9a);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-shadow: 0 0 35px rgba(229,9,20,0.75);
        }

        .subtitle {
            font-size: 1.05rem;
            font-weight: 400;
            color: var(--text-muted);
            max-width: 460px;
            margin-bottom: 22px;
        }

        .typewriter {
            font-size: 0.95rem;
            letter-spacing: 0.5px;
            height: 24px;
            margin-bottom: 30px;
            color: rgba(255,255,255,0.86);
        }

        .cursor {
            border-right: 2px solid #fff;
            animation: blink 0.7s infinite;
            margin-left: 2px;
        }

        @keyframes blink {
            50% { border-color: transparent; }
        }

        .hero-cta-group {
            display: flex;
            flex-wrap: wrap;
            gap: 14px;
            align-items: center;
            margin-bottom: 22px;
        }

        .btn-explore {
            padding: 14px 40px;
            font-size: 0.95rem;
            font-weight: 700;
            border-radius: 999px;
            text-transform: uppercase;
            letter-spacing: 2px;
            color: #fff;
            background: radial-gradient(circle at 30% 0%, rgba(255,255,255,0.18), transparent 65%),
                        linear-gradient(130deg, var(--red), var(--red-soft));
            border: none;
            position: relative;
            overflow: hidden;
            text-decoration: none !important;
            box-shadow: 0 10px 30px rgba(229,9,20,0.7);
            transition: 0.3s ease;
            display: inline-flex;
            align-items: center;
            justify-content: center;
        }

        .btn-explore::before {
            content: "";
            position: absolute;
            inset: -2px;
            border-radius: inherit;
            background: conic-gradient(from 40deg, transparent, rgba(255,255,255,0.75), transparent 55%);
            mix-blend-mode: screen;
            opacity: 0;
            transform: rotate(0deg);
            transition: opacity 0.4s;
        }

        .btn-explore:hover::before {
            opacity: 1;
            animation: spinGlow 2.8s linear infinite;
        }

        @keyframes spinGlow {
            to { transform: rotate(360deg); }
        }

        .btn-explore i {
            margin-left: 8px;
            transition: transform 0.25s;
        }

        .btn-explore:hover {
            transform: translateY(-3px) scale(1.03);
        }

        .btn-explore:hover i {
            transform: translateX(5px);
        }

        .btn-ghost {
            padding: 11px 18px;
            border-radius: 999px;
            border: 1px solid rgba(255,255,255,0.35);
            background: rgba(0,0,0,0.5);
            color: var(--text-muted);
            font-size: 0.85rem;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: 0.25s;
        }

        .btn-ghost:hover {
            background: rgba(255,255,255,0.08);
            color: #fff;
        }

        .btn-ghost i {
            color: var(--red);
        }

        .hero-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 18px;
            font-size: 0.78rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
        }

        .hero-meta span strong {
            color: #fff;
        }

        /* Scroll indicator */
        .scroll-indicator {
            position: absolute;
            left: 50%;
            bottom: 18px;
            transform: translateX(-50%);
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 6px;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 2px;
            color: rgba(255,255,255,0.7);
            cursor: pointer;
            text-decoration: none;
        }

        .scroll-mouse {
            width: 20px;
            height: 32px;
            border-radius: 12px;
            border: 1px solid rgba(255,255,255,0.7);
            display: flex;
            align-items: flex-start;
            justify-content: center;
            padding-top: 5px;
            overflow: hidden;
        }

        .scroll-wheel {
            width: 3px;
            height: 7px;
            border-radius: 999px;
            background: #fff;
            animation: scrollWheel 1.5s infinite;
        }

        @keyframes scrollWheel {
            0%   { transform: translateY(0); opacity: 1; }
            80%  { transform: translateY(12px); opacity: 0; }
            100% { transform: translateY(0); opacity: 0; }
        }

        /* ================== HERO RIGHT: TICKET ================== */
        .hero-right {
            position: relative;
            display: flex;
            justify-content: center;
        }

        .ticket {
            width: 100%;
            max-width: 420px;
            background: radial-gradient(circle at 0% 0%, rgba(255,255,255,0.04), transparent 55%),
                        linear-gradient(145deg, #0b0b0f, #1a0000);
            border-radius: 28px;
            padding: 18px 20px 20px;
            box-shadow:
                0 0 40px rgba(229,9,20,.8),
                0 25px 80px rgba(0,0,0,.95);
            position: relative;
            overflow: hidden;
            border: 2px solid rgba(255,255,255,.18);
            animation: floatCard 6s ease-in-out infinite alternate;
        }

        @keyframes floatCard {
            to { transform: translateY(-15px); }
        }

        .ticket::before {
            content: "";
            position: absolute;
            inset: -120px;
            background: radial-gradient(circle at 20% 0%, rgba(229,9,20,0.4), transparent 55%);
            opacity: 0.6;
            mix-blend-mode: screen;
        }

        .ticket-inner {
            position: relative;
            z-index: 1;
        }

        .ticket-logo {
            display: flex;
            justify-content: center;
            margin-bottom: 10px;
        }

        .ticket-logo-icon {
            width: 42px;
            height: 42px;
            border-radius: 16px;
            background: #f5f5f5;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 0 20px rgba(229,9,20,0.9);
        }

        .ticket-logo-icon i {
            color: var(--red);
            font-size: 1.3rem;
        }

        .ticket-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.7rem;
            letter-spacing: 1.5px;
            opacity: .9;
            margin-bottom: 14px;
            text-transform: uppercase;
        }

        .badge-premium {
            background: linear-gradient(120deg, var(--red), #ff6a6a);
            padding: 4px 10px;
            border-radius: 99px;
            font-weight: 700;
            box-shadow: 0 0 16px rgba(229,9,20,0.8);
        }

        .ticket-no {
            opacity: .7;
        }

        .ticket-route {
            display: grid;
            grid-template-columns: 1fr auto 1fr;
            text-align: center;
            margin: 8px 0 10px;
        }

        .ticket-route strong {
            font-size: 1.9rem;
            letter-spacing: 3px;
        }

        .ticket-route span {
            font-size: 0.7rem;
            opacity: .7;
            display: block;
            text-transform: uppercase;
        }

        .ticket-arrow {
            font-size: 1.6rem;
            color: var(--red);
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .ticket-info {
            display: grid;
            grid-template-columns: repeat(3,1fr);
            gap: 10px;
            margin-top: 14px;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .ticket-info div {
            background: rgba(255,255,255,0.06);
            padding: 8px;
            border-radius: 10px;
            text-align: center;
        }

        .ticket-info span {
            display: block;
            font-size: 0.7rem;
            opacity: .7;
            margin-bottom: 3px;
        }

        .ticket-footer {
            margin-top: 14px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.68rem;
            opacity: .8;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .ticket-scan {
            border: 1px dashed rgba(255,255,255,0.5);
            padding: 3px 10px;
            border-radius: 6px;
        }

        /* ================== STRIP ================== */
        .hero-strip {
            position: relative;
            z-index: 5;
            margin-top: -10px;
        }

        .strip-inner {
            max-width: 1100px;
            margin: 0 auto 40px;
            padding: 14px 22px;
            border-radius: 999px;
            background: rgba(0,0,0,0.85);
            backdrop-filter: blur(14px);
            border: 1px solid rgba(255,255,255,0.18);
            display: flex;
            flex-wrap: wrap;
            gap: 18px;
            justify-content: center;
        }

        .strip-item {
            min-width: 150px;
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 0.74rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
        }

        .strip-item strong {
            display: block;
            font-size: 0.9rem;
            color: #fff;
        }

        .strip-icon {
            width: 26px;
            height: 26px;
            border-radius: 999px;
            background: rgba(255,255,255,0.06);
            display: flex;
            align-items: center;
            justify-content: center;
            border: 1px solid rgba(255,255,255,0.22);
        }

        .strip-icon i {
            font-size: 0.9rem;
            color: var(--red);
        }

        /* ================== SECTIONS ================== */
        section {
            position: relative;
            z-index: 5;
        }

        #discover {
            padding: 40px 4vw 70px;
        }

        .section-heading {
            max-width: 1100px;
            margin: 0 auto 26px;
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
            gap: 10px;
        }

        .section-heading-left h2 {
            font-size: 1.8rem;
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-bottom: 4px;
        }

        .section-heading-left p {
            font-size: 0.9rem;
            color: var(--text-muted);
        }

        .section-heading-right {
            font-size: 0.8rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
            text-align: right;
        }

        .section-heading-right span {
            color: var(--red);
        }

        .features-grid {
            max-width: 1100px;
            margin: 0 auto;
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 22px;
        }

        .card-cine {
            padding: 22px 20px;
            border-radius: 20px;
            background: radial-gradient(circle at 0% 0%, rgba(255,255,255,0.06), transparent 60%),
                        linear-gradient(135deg, rgba(0,0,0,0.94), rgba(0,0,0,0.78));
            border: 1px solid rgba(255,255,255,0.18);
            box-shadow:
                0 12px 35px rgba(0,0,0,0.85),
                0 0 24px rgba(229,9,20,0.4);
            backdrop-filter: blur(16px);
            transition: transform 0.35s ease, box-shadow 0.35s ease, border-color 0.35s ease, background 0.35s ease;
            position: relative;
            overflow: hidden;
        }

        .card-cine::before {
            content: "";
            position: absolute;
            inset: -120px;
            background: radial-gradient(circle at 0% 0%, rgba(229,9,20,0.4), transparent 50%);
            opacity: 0;
            transition: opacity 0.45s;
        }

        .card-cine:hover {
            transform: translateY(-10px) scale(1.02);
            box-shadow:
                0 22px 55px rgba(0,0,0,0.9),
                0 0 40px rgba(229,9,20,0.8);
            border-color: rgba(255,255,255,0.3);
        }

        .card-cine:hover::before {
            opacity: 1;
        }

        .card-cine i {
            font-size: 2.1rem;
            color: var(--red);
            margin-bottom: 10px;
            filter: drop-shadow(0 0 16px rgba(229,9,20,0.7));
        }

        .card-cine h6 {
            font-size: 1.05rem;
            font-weight: 700;
            margin-bottom: 6px;
            letter-spacing: 1px;
            text-transform: uppercase;
        }

        .card-cine p {
            font-size: 0.9rem;
            opacity: 0.9;
            line-height: 1.6;
            color: var(--text-muted);
        }

        .card-meta {
            margin-top: 14px;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: rgba(255,255,255,0.6);
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .badge-soft {
            padding: 3px 10px;
            border-radius: 999px;
            border: 1px solid rgba(255,255,255,0.35);
            background: rgba(255,255,255,0.05);
            font-size: 0.7rem;
        }

        /* WHY SECTION */
        .section-dark {
            padding: 70px 6vw;
        }

        .section-dark h2 {
            text-transform: uppercase;
            letter-spacing: 2px;
            text-align: center;
            margin-bottom: 10px;
        }

        .section-dark p {
            text-align: center;
            color: var(--text-muted);
            font-size: 0.9rem;
            max-width: 620px;
            margin: 0 auto 30px;
        }

        .grid-3 {
            max-width: 1100px;
            margin: 0 auto;
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 22px;
        }

        .why-box {
            background: rgba(0,0,0,0.85);
            border-radius: 18px;
            padding: 22px;
            border: 1px solid rgba(255,255,255,0.16);
            box-shadow: 0 15px 35px rgba(0,0,0,0.85);
            backdrop-filter: blur(12px);
            font-size: 0.9rem;
            color: var(--text-muted);
            transition: 0.3s;
        }

        .why-box strong {
            display: block;
            margin-bottom: 8px;
            font-size: 1rem;
            color: #fff;
        }

        .why-box:hover {
            transform: translateY(-8px);
            box-shadow: 0 22px 50px rgba(0,0,0,0.9);
            border-color: rgba(229,9,20,0.7);
        }

        /* TIMELINE */
        .timeline {
            padding: 60px 6vw 80px;
        }

        .timeline-inner {
            max-width: 900px;
            margin: 0 auto;
            text-align: center;
        }

        .timeline-inner h2 {
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-bottom: 10px;
        }

        .timeline-inner p {
            color: var(--text-muted);
            font-size: 0.9rem;
            margin-bottom: 25px;
        }

        .timeline-steps {
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            gap: 16px;
        }

        .timeline-step {
            padding: 12px 18px;
            border-radius: 999px;
            border: 1px solid rgba(255,255,255,0.25);
            background: rgba(0,0,0,0.8);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .timeline-step i {
            color: var(--red);
        }

        /* CTA FINAL */
        .cta-final {
            padding: 80px 6vw 100px;
            text-align: center;
        }

        .cta-final h2 {
            text-transform: uppercase;
            letter-spacing: 3px;
            margin-bottom: 14px;
        }

        .cta-final p {
            color: var(--text-muted);
            font-size: 0.9rem;
            margin-bottom: 22px;
        }

        .cta-final a {
            padding: 15px 38px;
            border-radius: 999px;
            background: linear-gradient(130deg, var(--red), var(--red-soft));
            color: #fff;
            text-transform: uppercase;
            letter-spacing: 2px;
            font-size: 0.9rem;
            text-decoration: none;
            box-shadow: 0 15px 35px rgba(229,9,20,0.7);
            transition: 0.28s;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }

        .cta-final a:hover {
            transform: translateY(-3px) scale(1.03);
            box-shadow: 0 20px 45px rgba(229,9,20,0.9);
        }

        /* ================== RESPONSIVE ================== */
        @media (max-width: 992px) {
            .hero-inner {
                grid-template-columns: minmax(0, 1.2fr);
            }
            .hero-right {
                order: -1;
                margin-bottom: 18px;
            }
            .hero-wrapper {
                padding-top: 110px;
            }
            .section-heading {
                flex-direction: column;
                align-items: flex-start;
            }
            .section-heading-right {
                text-align: left;
            }
        }

        @media (max-width: 768px) {
            .navbar-glass {
                padding: 12px 18px;
            }
            .hero-inner {
                gap: 22px;
            }
            .features-grid,
            .grid-3 {
                grid-template-columns: minmax(0, 1fr);
            }
            .strip-inner {
                border-radius: 26px;
            }
            .hero-meta {
                gap: 12px;
            }
        }

        @media (max-width: 480px) {
            .hero-wrapper {
                padding-inline: 18px;
            }
            .btn-explore,
            .btn-ghost {
                width: 100%;
                justify-content: center;
            }
            .strip-inner {
                padding: 12px 14px;
            }
        }
    </style>
</head>
<body>
    <!-- BACKGROUND LAYERS -->
    <div class="bg-intro"></div>
    <div class="noise-overlay"></div>
    <div class="red-overlay"></div>
    <div class="particles" id="particles"></div>

    <!-- NAVBAR -->
    <header class="navbar-glass">
        <div class="brand-mini">
            <div class="brand-mini-logo">
                <i class="fas fa-plane-departure"></i>
            </div>
            <div class="brand-mini-text">WL <span>Airline</span></div>
        </div>
        <div class="nav-actions">
            <a href="login.php" class="btn-nav">
                <i class="fa-regular fa-circle-user me-1"></i> Đăng nhập
            </a>
            <a href="flight.php" class="btn-nav btn-nav-primary">
                Đặt vé ngay
            </a>
        </div>
    </header>

    <!-- HERO -->
    <main>
        <section class="hero-wrapper">
            <div class="hero-inner">
                <!-- LEFT -->
                <div data-aos="fade-right">
                    <div class="hero-logo">
                        <div class="hero-logo-icon">
                            <i class="fas fa-plane-departure"></i>
                        </div>
                        <div class="hero-logo-text">
                            WL <span>Airline</span>
                        </div>
                    </div>

                    <div class="hero-tagline">
                        <i class="fa-solid fa-clapperboard"></i>
                        Cinematic Class of Aviation
                    </div>

                    <h1 class="brand-title">
                        WL <span>AIRLINE</span>
                    </h1>

                    <p class="subtitle">
                        Trải nghiệm chuyến bay như một bộ phim điện ảnh – nơi từng khoảnh khắc
                        đều được dàn dựng để hoàn hảo, từ mặt đất đến bầu trời.
                    </p>

                    <div class="typewriter">
                        <span id="typing-text"></span><span class="cursor">|</span>
                    </div>

                    <div class="hero-cta-group">
                        <a href="home.php" class="btn-explore">
                            Bắt đầu hành trình <i class="fas fa-plane"></i>
                        </a>
                        <a href="#discover" class="btn-ghost">
                            <i class="fa-solid fa-circle-play"></i>
                            Khám phá WL Airline
                        </a>
                    </div>

                    <div class="hero-meta">
                        <span><strong>100+ điểm đến</strong> trên toàn thế giới</span>
                        <span><strong>5★ an toàn</strong> được chứng nhận</span>
                        <span><strong>24/7</strong> chăm sóc & hỗ trợ</span>
                    </div>
                </div>

                <!-- RIGHT: TICKET -->
                <div class="hero-right" data-aos="fade-left" data-aos-delay="150">
                    <div class="ticket">
                        <div class="ticket-inner">
                            <div class="ticket-logo">
                                <div class="ticket-logo-icon">
                                    <i class="fas fa-plane-departure"></i>
                                </div>
                            </div>

                            <div class="ticket-header">
                                <span class="badge-premium">Premium Cinema Flight</span>
                                <span class="ticket-no">E-TICKET · WL A123</span>
                            </div>

                            <div class="ticket-route">
                                <div>
                                    <strong>SGN</strong>
                                    <span>Ho Chi Minh City</span>
                                </div>
                                <div class="ticket-arrow">
                                    <i class="fas fa-plane"></i>
                                </div>
                                <div>
                                    <strong>LHR</strong>
                                    <span>London Heathrow</span>
                                </div>
                            </div>

                            <div class="ticket-info">
                                <div><span>Date</span>12 Dec 2025</div>
                                <div><span>Gate</span>A19</div>
                                <div><span>Seat</span>1A</div>
                                <div><span>Boarding</span>22:45</div>
                                <div><span>Class</span>First</div>
                                <div><span>Passenger</span>You</div>
                            </div>

                            <div class="ticket-footer">
                                <span>WL Airline Official Boarding Pass</span>
                                <span class="ticket-scan">Scan & Fly</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Scroll indicator -->
            <a href="#discover" class="scroll-indicator">
                <div class="scroll-mouse">
                    <div class="scroll-wheel"></div>
                </div>
                <span>Cuộn xuống</span>
            </a>
        </section>

        <!-- STRIP -->
        <div class="hero-strip" data-aos="fade-up" data-aos-delay="120">
            <div class="strip-inner">
                <div class="strip-item">
                    <div class="strip-icon">
                        <i class="fa-solid fa-shield-halved"></i>
                    </div>
                    <div>
                        <strong>An toàn tuyệt đối</strong>
                        Tỉ lệ sự cố cực thấp
                    </div>
                </div>
                <div class="strip-item">
                    <div class="strip-icon">
                        <i class="fa-solid fa-champagne-glasses"></i>
                    </div>
                    <div>
                        <strong>Dịch vụ hạng nhất</strong>
                        Ẩm thực chuẩn fine-dining
                    </div>
                </div>
                <div class="strip-item">
                    <div class="strip-icon">
                        <i class="fa-solid fa-globe-asia"></i>
                    </div>
                    <div>
                        <strong>Kết nối toàn cầu</strong>
                        Hơn 100+ thành phố
                    </div>
                </div>
            </div>
        </div>

        <!-- FEATURES -->
        <section id="discover">
            <div class="section-heading" data-aos="fade-up">
                <div class="section-heading-left">
                    <h2>Trải nghiệm WL Airline</h2>
                    <p>
                        Từ khoảnh khắc check-in đến khi chạm bánh xuống đường băng,
                        mọi thứ đều được thiết kế như một bộ phim với cốt truyện, cảm xúc và dư âm.
                    </p>
                </div>
                <div class="section-heading-right">
                    Lướt nhẹ xuống & cảm nhận<br>
                    <span>Cinematic Journey</span>
                </div>
            </div>

            <div class="features-grid">
                <div class="card-cine" data-aos="fade-up" data-aos-delay="50">
                    <i class="fas fa-shield-alt"></i>
                    <h6>An toàn tuyệt đối</h6>
                    <p>
                        Đội bay được đào tạo chuẩn quốc tế, máy bay thế hệ mới, quy trình bảo dưỡng nghiêm ngặt
                        và hệ thống giám sát 24/7 giúp đảm bảo an toàn tối đa.
                    </p>
                    <div class="card-meta">
                        <span class="badge-soft">5★ Safety Rated</span>
                        <span>Giám sát 24/7</span>
                    </div>
                </div>

                <div class="card-cine" data-aos="fade-up" data-aos-delay="150">
                    <i class="fas fa-wine-glass-alt"></i>
                    <h6>Dịch vụ hạng nhất</h6>
                    <p>
                        Thực đơn được tuyển chọn bởi các đầu bếp danh tiếng, phòng chờ sang trọng,
                        ghế ngả phẳng cùng hệ thống giải trí chuẩn rạp chiếu phim.
                    </p>
                    <div class="card-meta">
                        <span class="badge-soft">Signature Lounge</span>
                        <span>Fine Dining & More</span>
                    </div>
                </div>

                <div class="card-cine" data-aos="fade-up" data-aos-delay="250">
                    <i class="fas fa-globe-asia"></i>
                    <h6>Kết nối toàn cầu</h6>
                    <p>
                        Hơn 100+ điểm đến trên khắp thế giới, kết nối mượt mà giữa các châu lục,
                        nâng tầm mọi hành trình công tác, du lịch hay trải nghiệm cá nhân.
                    </p>
                    <div class="card-meta">
                        <span class="badge-soft">100+ Destinations</span>
                        <span>Seamless Connection</span>
                    </div>
                </div>
            </div>
        </section>

        <!-- WHY WL AIRLINE -->
        <section class="section-dark">
            <h2>Vì sao chọn WL Airline?</h2>
            <p>
                Không chỉ là một chuyến bay, WL Airline mang đến một hành trình được đạo diễn tỉ mỉ
                – nơi bạn là nhân vật chính, còn chúng tôi là ekip đứng sau mọi khung hình hoàn hảo.
            </p>
            <div class="grid-3">
                <div class="why-box" data-aos="fade-up" data-aos-delay="50">
                    <strong>Đội ngũ quốc tế</strong>
                    Phi công & tiếp viên được tuyển chọn kỹ lưỡng, giàu kinh nghiệm, thao tác chuẩn xác trong mọi tình huống.
                </div>
                <div class="why-box" data-aos="fade-up" data-aos-delay="150">
                    <strong>Không gian như rạp phim</strong>
                    Ánh sáng, âm thanh, ghế ngồi và bầu không khí được tối ưu để bạn có cảm giác như đang ở một mini cinema trên mây.
                </div>
                <div class="why-box" data-aos="fade-up" data-aos-delay="250">
                    <strong>Công nghệ hàng đầu</strong>
                    Hệ thống giải trí, Wi-Fi tốc độ cao, quản lý hành trình thông minh giúp bạn chủ động từng phút giây trên chuyến bay.
                </div>
            </div>
        </section>

        <!-- JOURNEY TIMELINE -->
        <section class="timeline">
            <div class="timeline-inner" data-aos="fade-up">
                <h2>Hành trình cinematic của bạn</h2>
                <p>
                    Mỗi chặng đều là một “cảnh quay” được dàn dựng chỉn chu – từ lúc bạn đặt vé
                    đến khi bước qua cổng arrivals.
                </p>
                <div class="timeline-steps">
                    <div class="timeline-step"><i class="fa-solid fa-ticket"></i> Đặt vé</div>
                    <div class="timeline-step"><i class="fa-solid fa-id-card"></i> Check-in</div>
                    <div class="timeline-step"><i class="fa-solid fa-couch"></i> Lounge</div>
                    <div class="timeline-step"><i class="fa-solid fa-door-open"></i> Boarding</div>
                    <div class="timeline-step"><i class="fa-solid fa-plane-up"></i> Take-off</div>
                    <div class="timeline-step"><i class="fa-solid fa-mug-hot"></i> Dịch vụ trên không</div>
                    <div class="timeline-step"><i class="fa-solid fa-plane-arrival"></i> Landing</div>
                </div>
            </div>
        </section>

        <!-- CTA FINAL -->
        <section class="cta-final">
            <h2>Sẵn sàng cho chuyến bay đẳng cấp?</h2>
            <p>
                Chỉ một cú nhấp chuột, cả hành trình cinematic đang đợi bạn ở phía trước.
                Chọn điểm đến, phần còn lại cứ để WL Airline lo.
            </p>
            <a href="home.php">
                Đặt vé ngay <i class="fas fa-plane-departure"></i>
            </a>
        </section>
    </main>

    <!-- SCRIPTS -->
    <script src="https://unpkg.com/aos@2.3.1/dist/aos.js"></script>
    <script>
        // AOS init
        AOS.init({
            once: true,
            duration: 900,
            easing: 'ease-out-quint'
        });

        // Particles
        const particleContainer = document.getElementById('particles');
        const PARTICLE_COUNT = 40;
        for (let i = 0; i < PARTICLE_COUNT; i++) {
            const p = document.createElement('div');
            p.classList.add('particle');
            p.style.left = Math.random() * 100 + '%';
            p.style.top = Math.random() * 100 + '%';
            const duration = 5 + Math.random() * 6;
            const delay = Math.random() * -duration;
            p.style.animationDuration = duration + 's';
            p.style.animationDelay = delay + 's';
            p.style.opacity = 0.2 + Math.random() * 0.7;
            particleContainer.appendChild(p);
        }

        // Typewriter
        const texts = [
            "Nơi bắt đầu những chuyến bay không giới hạn.",
            "Hành trình của sự đẳng cấp.",
            "Chạm đến tương lai của ngành hàng không."
        ];
        let currentText = 0;
        let charIndex = 0;
        let isDeleting = false;
        const typingElement = document.getElementById('typing-text');

        function typeLoop() {
            const fullText = texts[currentText];

            if (!isDeleting) {
                charIndex++;
                typingElement.textContent = fullText.substring(0, charIndex);
                if (charIndex === fullText.length) {
                    isDeleting = true;
                    setTimeout(typeLoop, 1500);
                    return;
                }
            } else {
                charIndex--;
                typingElement.textContent = fullText.substring(0, charIndex);
                if (charIndex === 0) {
                    isDeleting = false;
                    currentText = (currentText + 1) % texts.length;
                }
            }

            const speed = isDeleting ? 40 : 70;
            setTimeout(typeLoop, speed);
        }
        typeLoop();
    </script>
</body>
</html>

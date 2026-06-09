// UI message catalogs, one per supported locale.
//
// English is the source-of-truth catalog and the react-intl fallback
// (defaultLocale="en"): `messagesFor` merges the active locale over English,
// so any key missing from a translated catalog renders the English string
// rather than the raw key. Translated catalogs are therefore `Partial` — a
// locale only needs to carry the keys it actually localizes, and the rest
// degrade gracefully to English.
//
// This catalog covers the application shell every operator sees (top bar +
// sidebar navigation), translated across all supported locales. Feature
// screens render their strings via <FormattedMessage defaultMessage=…>, which
// react-intl resolves to the catalog entry when present and to the inline
// English default otherwise — so screens can be localized incrementally
// without ever showing a raw message id.

import type { Locale } from "./locales";

export type MessageKey =
  | "app.subtitle"
  | "topbar.tenant"
  | "topbar.signOut"
  | "topbar.language"
  | "topbar.menu"
  | "nav.group.overview"
  | "nav.group.govern"
  | "nav.group.lifecycle"
  | "nav.group.preferences"
  | "nav.dashboard"
  | "nav.policies"
  | "nav.packs"
  | "nav.requests"
  | "nav.grants"
  | "nav.reviews"
  | "nav.directory"
  | "nav.settings";

type Catalog = Record<MessageKey, string>;

const en: Catalog = {
  "app.subtitle": "Access console",
  "topbar.tenant": "Tenant",
  "topbar.signOut": "Sign out",
  "topbar.language": "Language",
  "topbar.menu": "Open navigation menu",
  "nav.group.overview": "Overview",
  "nav.group.govern": "Govern",
  "nav.group.lifecycle": "Lifecycle",
  "nav.group.preferences": "Preferences",
  "nav.dashboard": "Dashboard",
  "nav.policies": "Access policies",
  "nav.packs": "Policy packs",
  "nav.requests": "Access requests",
  "nav.grants": "Grants",
  "nav.reviews": "Access reviews",
  "nav.directory": "Directory",
  "nav.settings": "Settings",
};

const zhHans: Partial<Catalog> = {
  "app.subtitle": "访问控制台",
  "topbar.tenant": "租户",
  "topbar.signOut": "退出登录",
  "topbar.language": "语言",
  "topbar.menu": "打开导航菜单",
  "nav.group.overview": "概览",
  "nav.group.govern": "治理",
  "nav.group.lifecycle": "生命周期",
  "nav.group.preferences": "偏好设置",
  "nav.dashboard": "概览",
  "nav.policies": "访问策略",
  "nav.packs": "策略包",
  "nav.requests": "访问请求",
  "nav.grants": "授权",
  "nav.reviews": "访问审查",
  "nav.directory": "目录",
  "nav.settings": "设置",
};

const zhHant: Partial<Catalog> = {
  "app.subtitle": "存取主控台",
  "topbar.tenant": "租戶",
  "topbar.signOut": "登出",
  "topbar.language": "語言",
  "topbar.menu": "開啟導覽選單",
  "nav.group.overview": "概覽",
  "nav.group.govern": "治理",
  "nav.group.lifecycle": "生命週期",
  "nav.group.preferences": "偏好設定",
  "nav.dashboard": "概覽",
  "nav.policies": "存取原則",
  "nav.packs": "原則套件",
  "nav.requests": "存取請求",
  "nav.grants": "授權",
  "nav.reviews": "存取審查",
  "nav.directory": "目錄",
  "nav.settings": "設定",
};

const ms: Partial<Catalog> = {
  "app.subtitle": "Konsol Akses",
  "topbar.tenant": "Penyewa",
  "topbar.signOut": "Log keluar",
  "topbar.language": "Bahasa",
  "topbar.menu": "Buka menu navigasi",
  "nav.group.overview": "Gambaran keseluruhan",
  "nav.group.govern": "Tadbir urus",
  "nav.group.lifecycle": "Kitar hayat",
  "nav.group.preferences": "Keutamaan",
  "nav.dashboard": "Papan pemuka",
  "nav.policies": "Dasar akses",
  "nav.packs": "Pek dasar",
  "nav.requests": "Permintaan akses",
  "nav.grants": "Pemberian akses",
  "nav.reviews": "Semakan akses",
  "nav.directory": "Direktori",
  "nav.settings": "Tetapan",
};

const id: Partial<Catalog> = {
  "app.subtitle": "Konsol Akses",
  "topbar.tenant": "Tenant",
  "topbar.signOut": "Keluar",
  "topbar.language": "Bahasa",
  "topbar.menu": "Buka menu navigasi",
  "nav.group.overview": "Ikhtisar",
  "nav.group.govern": "Tata kelola",
  "nav.group.lifecycle": "Siklus hidup",
  "nav.group.preferences": "Preferensi",
  "nav.dashboard": "Dasbor",
  "nav.policies": "Kebijakan akses",
  "nav.packs": "Paket kebijakan",
  "nav.requests": "Permintaan akses",
  "nav.grants": "Pemberian akses",
  "nav.reviews": "Tinjauan akses",
  "nav.directory": "Direktori",
  "nav.settings": "Pengaturan",
};

const th: Partial<Catalog> = {
  "app.subtitle": "คอนโซลการเข้าถึง",
  "topbar.tenant": "ผู้เช่า",
  "topbar.signOut": "ออกจากระบบ",
  "topbar.language": "ภาษา",
  "topbar.menu": "เปิดเมนูนำทาง",
  "nav.group.overview": "ภาพรวม",
  "nav.group.govern": "การกำกับดูแล",
  "nav.group.lifecycle": "วงจรชีวิต",
  "nav.group.preferences": "การตั้งค่าส่วนตัว",
  "nav.dashboard": "แดชบอร์ด",
  "nav.policies": "นโยบายการเข้าถึง",
  "nav.packs": "ชุดนโยบาย",
  "nav.requests": "คำขอการเข้าถึง",
  "nav.grants": "สิทธิ์ที่ได้รับ",
  "nav.reviews": "การตรวจสอบการเข้าถึง",
  "nav.directory": "ไดเรกทอรี",
  "nav.settings": "การตั้งค่า",
};

const vi: Partial<Catalog> = {
  "app.subtitle": "Bảng điều khiển Truy cập",
  "topbar.tenant": "Người thuê",
  "topbar.signOut": "Đăng xuất",
  "topbar.language": "Ngôn ngữ",
  "topbar.menu": "Mở menu điều hướng",
  "nav.group.overview": "Tổng quan",
  "nav.group.govern": "Quản trị",
  "nav.group.lifecycle": "Vòng đời",
  "nav.group.preferences": "Tùy chọn",
  "nav.dashboard": "Bảng điều khiển",
  "nav.policies": "Chính sách truy cập",
  "nav.packs": "Gói chính sách",
  "nav.requests": "Yêu cầu truy cập",
  "nav.grants": "Quyền được cấp",
  "nav.reviews": "Đánh giá truy cập",
  "nav.directory": "Thư mục",
  "nav.settings": "Cài đặt",
};

const ja: Partial<Catalog> = {
  "app.subtitle": "アクセスコンソール",
  "topbar.tenant": "テナント",
  "topbar.signOut": "サインアウト",
  "topbar.language": "言語",
  "topbar.menu": "ナビゲーションメニューを開く",
  "nav.group.overview": "概要",
  "nav.group.govern": "ガバナンス",
  "nav.group.lifecycle": "ライフサイクル",
  "nav.group.preferences": "環境設定",
  "nav.dashboard": "ダッシュボード",
  "nav.policies": "アクセスポリシー",
  "nav.packs": "ポリシーパック",
  "nav.requests": "アクセスリクエスト",
  "nav.grants": "付与",
  "nav.reviews": "アクセスレビュー",
  "nav.directory": "ディレクトリ",
  "nav.settings": "設定",
};

const ko: Partial<Catalog> = {
  "app.subtitle": "액세스 콘솔",
  "topbar.tenant": "테넌트",
  "topbar.signOut": "로그아웃",
  "topbar.language": "언어",
  "topbar.menu": "탐색 메뉴 열기",
  "nav.group.overview": "개요",
  "nav.group.govern": "거버넌스",
  "nav.group.lifecycle": "수명 주기",
  "nav.group.preferences": "기본 설정",
  "nav.dashboard": "대시보드",
  "nav.policies": "액세스 정책",
  "nav.packs": "정책 팩",
  "nav.requests": "액세스 요청",
  "nav.grants": "권한 부여",
  "nav.reviews": "액세스 검토",
  "nav.directory": "디렉터리",
  "nav.settings": "설정",
};

const ar: Partial<Catalog> = {
  "app.subtitle": "وحدة تحكم الوصول",
  "topbar.tenant": "المستأجر",
  "topbar.signOut": "تسجيل الخروج",
  "topbar.language": "اللغة",
  "topbar.menu": "فتح قائمة التنقل",
  "nav.group.overview": "نظرة عامة",
  "nav.group.govern": "الحوكمة",
  "nav.group.lifecycle": "دورة الحياة",
  "nav.group.preferences": "التفضيلات",
  "nav.dashboard": "لوحة المعلومات",
  "nav.policies": "سياسات الوصول",
  "nav.packs": "حزم السياسات",
  "nav.requests": "طلبات الوصول",
  "nav.grants": "المنح",
  "nav.reviews": "مراجعات الوصول",
  "nav.directory": "الدليل",
  "nav.settings": "الإعدادات",
};

const de: Partial<Catalog> = {
  "app.subtitle": "Zugriffskonsole",
  "topbar.tenant": "Mandant",
  "topbar.signOut": "Abmelden",
  "topbar.language": "Sprache",
  "topbar.menu": "Navigationsmenü öffnen",
  "nav.group.overview": "Übersicht",
  "nav.group.govern": "Governance",
  "nav.group.lifecycle": "Lebenszyklus",
  "nav.group.preferences": "Präferenzen",
  "nav.dashboard": "Dashboard",
  "nav.policies": "Zugriffsrichtlinien",
  "nav.packs": "Richtlinienpakete",
  "nav.requests": "Zugriffsanfragen",
  "nav.grants": "Berechtigungen",
  "nav.reviews": "Zugriffsüberprüfungen",
  "nav.directory": "Verzeichnis",
  "nav.settings": "Einstellungen",
};

const fr: Partial<Catalog> = {
  "app.subtitle": "Console d'accès",
  "topbar.tenant": "Locataire",
  "topbar.signOut": "Se déconnecter",
  "topbar.language": "Langue",
  "topbar.menu": "Ouvrir le menu de navigation",
  "nav.group.overview": "Aperçu",
  "nav.group.govern": "Gouvernance",
  "nav.group.lifecycle": "Cycle de vie",
  "nav.group.preferences": "Préférences",
  "nav.dashboard": "Tableau de bord",
  "nav.policies": "Politiques d'accès",
  "nav.packs": "Packs de règles",
  "nav.requests": "Demandes d'accès",
  "nav.grants": "Attributions",
  "nav.reviews": "Revues d'accès",
  "nav.directory": "Annuaire",
  "nav.settings": "Paramètres",
};

const CATALOGS: Record<Locale, Partial<Catalog>> = {
  en,
  "zh-Hans": zhHans,
  "zh-Hant": zhHant,
  ms,
  id,
  th,
  vi,
  ja,
  ko,
  ar,
  de,
  fr,
};

// messagesFor merges the requested locale over the full English catalog so any
// untranslated key falls back to English (rather than rendering a raw id).
export function messagesFor(locale: Locale): Record<string, string> {
  return { ...en, ...CATALOGS[locale] };
}

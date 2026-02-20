/* android_apk_dex_advanced.yar
 * Advanced detection for Android APK/DEX: loaders, overlays, SMS stealers, persistence, packers, anti-analysis, exfil/C2.
 * Author: ivan-gate
 */

/* ================= Helpers ================= */

private rule __is_zip_like        { condition: uint32(0) == 0x504B0304 }                 // ZIP (APK/AAB base)
private rule __has_apk_markers    { condition: __is_zip_like and ( "AndroidManifest.xml" ascii and "classes.dex" ascii ) }
private rule __is_dex             { condition: uint32(0) == 0x6465780A }                 // "dex\n"
private rule __apk_or_dex         { condition: __has_apk_markers or __is_dex }
private rule __smallish_mobile    { condition: filesize > 20KB and filesize < 200MB }

/* ================= Dangerous permissions & components (Manifest) ================= */

rule ANDROID_Dangerous_Permissions_And_Components
{
  meta: category="android-manifest" severity="medium" rationale="опасные пермишены/компоненты"
  strings:
    $p1 = "READ_SMS" ascii nocase
    $p2 = "RECEIVE_SMS" ascii nocase
    $p3 = "SEND_SMS" ascii nocase
    $p4 = "READ_CONTACTS" ascii nocase
    $p5 = "READ_CALL_LOG" ascii nocase
    $p6 = "WRITE_SETTINGS" ascii nocase
    $p7 = "SYSTEM_ALERT_WINDOW" ascii nocase
    $p8 = "REQUEST_INSTALL_PACKAGES" ascii nocase
    $p9 = "BIND_ACCESSIBILITY_SERVICE" ascii nocase
    $b1 = "RECEIVE_BOOT_COMPLETED" ascii nocase
    $s1 = "START_STICKY" ascii          // как строка в коде
    $d1 = "android:debuggable=\"true\"" ascii
  condition:
    __apk_or_dex and __smallish_mobile and
    ( 2 of ($p*) or $b1 or $s1 or $d1 )
}

/* ================= WebView loaders / JS-инжекты ================= */

rule ANDROID_WebView_JS_Loader
{
  meta: category="loader" severity="high" rationale="WebView loadUrl('javascript:'), addJavascriptInterface, evalJS"
  strings:
    $wv1 = "Landroid/webkit/WebView;->loadUrl" ascii
    $wv2 = "Landroid/webkit/WebView;->evaluateJavascript" ascii
    $wv3 = "Landroid/webkit/WebView;->addJavascriptInterface" ascii
    $js1 = "javascript:" ascii
    $dl1 = "Lokhttp3/OkHttpClient" ascii
    $dl2 = "Ljava/net/HttpURLConnection" ascii
  condition:
    __apk_or_dex and __smallish_mobile and
    ( ($wv1 or $wv2) and ($js1 or $wv3) ) or ( $wv3 and ( $dl1 or $dl2 ) )
}

/* ================= Overlay/Accessibility фишинг ================= */

rule ANDROID_Overlay_Accessibility_Phishing
{
  meta: category="phishing" severity="high" rationale="SYSTEM_ALERT_WINDOW + TYPE_APPLICATION_OVERLAY + AccessibilityService"
  strings:
    $ol1 = "SYSTEM_ALERT_WINDOW" ascii
    $ol2 = "TYPE_APPLICATION_OVERLAY" ascii
    $ac1 = "Landroid/accessibilityservice/AccessibilityService;" ascii
    $ac2 = "TYPE_VIEW_TEXT_CHANGED" ascii
    $ac3 = "FLAG_INCLUDE_NOT_IMPORTANT_VIEWS" ascii
    $m1  = "setSecure" ascii             // Settings.Secure
    $m2  = "canDrawOverlays" ascii
  condition:
    __apk_or_dex and __smallish_mobile and
    ( ( $ol1 or $m2 or $ol2 ) and ( $ac1 or $ac2 or $ac3 ) )
}

/* ================= SMS/Контакты/Клипер стиллинг ================= */

rule ANDROID_SMS_Contacts_Clipper_Steal
{
  meta: category="credential-access" severity="high" rationale="Telephony/SMS и content:// провайдеры"
  strings:
    $sm1 = "Landroid/telephony/SmsManager;->sendTextMessage" ascii
    $sm2 = "content://sms" ascii
    $ct1 = "content://contacts" ascii
    $cr1 = "Landroid/content/ContentResolver;->query" ascii
    $cb1 = "Landroid/content/ClipboardManager;->getPrimaryClip" ascii
    $cc1 = "setPrimaryClip" ascii
  condition:
    __apk_or_dex and __smallish_mobile and
    ( ($cr1 and ( $sm2 or $ct1 )) or $sm1 or ($cb1 and $cc1) )
}

/* ================= Автозапуск/сервисы/персистентность ================= */

rule ANDROID_Boot_Start_Persistence
{
  meta: category="persistence" severity="medium" rationale="BOOT_COMPLETED + старт сервисов"
  strings:
    $rc1 = "RECEIVE_BOOT_COMPLETED" ascii
    $rc2 = "BOOT_COMPLETED" ascii
    $sv1 = "Landroid/app/Service;->onStartCommand" ascii
    $st1 = "START_STICKY" ascii
    $al1 = "AlarmManager" ascii
    $wj1 = "WakeLock" ascii
  condition:
    __apk_or_dex and ( ( $rc1 or $rc2 ) and ( $sv1 or $st1 or $al1 or $wj1 ) )
}

/* ================= Дропперы/установка APK ================= */

rule ANDROID_Dropper_Install_APK
{
  meta: category="dropper" severity="high" rationale="install package/vending/pm install"
  strings:
    $ri1 = "REQUEST_INSTALL_PACKAGES" ascii
    $ai1 = "android.intent.action.INSTALL_PACKAGE" ascii
    $pi1 = "pm install" ascii
    $fd1 = "FileProvider" ascii
    $uri = "content://" ascii
  condition:
    __apk_or_dex and __smallish_mobile and
    ( $ri1 or $ai1 or ( $fd1 and $uri ) or $pi1 )
}

/* ================= Экcфиль/C2 (Discord/Telegram/gate.php/Firebase) ================= */

rule ANDROID_Exfil_HTTP_Webhooks_C2
{
  meta: category="exfiltration" severity="high" rationale="webhooks/гейты/okhttp"
  strings:
    $dc = "https://discord.com/api/webhooks" ascii
    $tg = "https://api.telegram.org/bot" ascii
    $gt = "/gate.php" ascii
    $up = "/upload.php" ascii
    $fh = "firebaseio.com" ascii
    $rt = "firebasestorage.googleapis.com" ascii
    $ok = "Lokhttp3/OkHttpClient" ascii
  condition:
    __apk_or_dex and __smallish_mobile and
    ( $dc or $tg or $gt or $up or $fh or $rt or $ok )
}

/* ================= Популярные пакеры/обфускаторы ================= */

rule ANDROID_Packer_Obfuscators
{
  meta: category="packer/obfuscation" severity="medium" rationale="jiagu/ijiami/360/dexprotector/secneo"
  strings:
    $jg1 = "libjiagu" ascii
    $jg2 = "com.qihoo.util.StubApp" ascii
    $im1 = "ijiami" ascii
    $dp1 = "DexProtector" ascii
    $sn1 = "libsecneo" ascii
    $sh1 = "libshella" ascii
    $dh1 = "libDexHelper" ascii
  condition:
    __apk_or_dex and ( 1 of ($jg1,$jg2,$im1,$dp1,$sn1,$sh1,$dh1) )
}

/* ================= Anti-debug/Anti-Frida/Эмулятор ================= */

rule ANDROID_AntiDebug_Frida_Emu
{
  meta: category="evasion" severity="medium" rationale="Frida/Debug/Emulator/QEMU"
  strings:
    $fd1 = "frida" ascii nocase
    $fd2 = "re.frida.server" ascii
    $db1 = "Landroid/os/Debug;->isDebuggerConnected" ascii
    $tr1 = "TracerPid" ascii
    $em1 = "goldfish" ascii
    $em2 = "ranchu" ascii
    $em3 = "generic" ascii
    $gm1 = "Genymotion" ascii
    $vb1 = "vbox" ascii
    $gp1 = "getprop" ascii
    $qm1 = "qemu" ascii
  condition:
    __apk_or_dex and __smallish_mobile and
    ( 2 of ($fd1,$fd2,$db1,$tr1,$em1,$em2,$em3,$gm1,$vb1,$gp1,$qm1) )
}

/* ================= Кража токенов/секретов ================= */

rule ANDROID_Tokens_Secrets_Grab
{
  meta: category="secrets" severity="medium" rationale="токены почты/мессенджеров/cloud"
  strings:
    $dc = /[MN][A-Za-z\\d]{23}\\.[A-Za-z\\d_-]{6}\\.[A-Za-z\\d_-]{27}/ ascii
    $tg = /[\w\-]{24,35}:[A-Za-z0-9_-]{30,40}/ ascii
    $gh = "ghp_" ascii
    $aw = "AWS_SECRET_ACCESS_KEY" ascii
    $gc = "GOOGLE_API_KEY" ascii
  condition:
    __apk_or_dex and ( $dc or $tg or $gh or $aw or $gc )
}

/* ================= High-Confidence COMBOS (низкий FP) ================= */

/* HC1: Overlay/Accessibility + exfil/C2 */
rule ANDROID_HC_Overlay_Exfil
{
  meta: category="combo" severity="critical" note="фишинг оверлеем + сеть/C2"
  condition:
    ANDROID_Overlay_Accessibility_Phishing and ANDROID_Exfil_HTTP_Webhooks_C2
}

/* HC2: WebView loader + dangerous permissions */
rule ANDROID_HC_WebView_Perms
{
  meta: category="combo" severity="critical" note="JS-инжект во WebView + опасные пермишены"
  condition:
    ANDROID_WebView_JS_Loader and ANDROID_Dangerous_Permissions_And_Components
}

/* HC3: Boot persistence + SMS/Contacts steal + exfil */
rule ANDROID_HC_Persist_Steal_Exfil
{
  meta: category="combo" severity="critical" note="автозапуск + стиллинг + вывод"
  condition:
    ANDROID_Boot_Start_Persistence and ANDROID_SMS_Contacts_Clipper_Steal and ANDROID_Exfil_HTTP_Webhooks_C2
}

/* HC4: Dropper + install packages + packer present */
rule ANDROID_HC_Dropper_Packer
{
  meta: category="combo" severity="high" note="дроппер, устанавливающий другие APK, упакован"
  condition:
    ANDROID_Dropper_Install_APK and ANDROID_Packer_Obfuscators
}

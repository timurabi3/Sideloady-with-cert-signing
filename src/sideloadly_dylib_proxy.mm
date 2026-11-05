// sideloadly_dylib_proxy.mm
// ~~~~~~~~~~~~~~~~~~~~~~~~~
// Native macOS (x86_64) Objective-C++ & Qt5 UI proxy dylib for Sideloadly v0.72.
//
// Loaded at `@executable_path/../Frameworks/sideloadly.dylib`:
//   1. Forwards `PyInit_sideloadly_wrap()` to `sideloadly_orig.dylib`.
//   2. Appends `<App>/Contents/Frameworks` to `sys.path` and calls
//      `sideloadly_cert_hook.install_sideloadly_hooks()`.
//   3. Injects a native Qt5 "Apple Developer Certificate (.p12 + .mobileprovision)"
//      group box directly inside Sideloadly's "Advanced Options" panel with full
//      Drag-and-Drop + File Upload support for `.p12` and `.mobileprovision` files.
//   4. Also provides a "Certificate Signing" macOS menu bar item.

#import <Cocoa/Cocoa.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Embedded CPython C-API declarations (resolved dynamically at runtime)
// ---------------------------------------------------------------------------
extern "C" {
    typedef void* PyObject;
    extern int PyRun_SimpleString(const char *command);
    extern int Py_IsInitialized(void);
    extern int PyGILState_Ensure(void);
    extern void PyGILState_Release(int);
    extern void* PyErr_Occurred(void);
    extern void PyErr_Print(void);
}

// ---------------------------------------------------------------------------
// Minimal ABI-accurate Qt 5.15.2 C++ bindings (QtCore / QtGui / QtWidgets)
// ---------------------------------------------------------------------------
struct QArrayData {
    int ref;
    int size;
    uint32_t alloc : 31;
    uint32_t capacityReserved : 1;
    ptrdiff_t offset;
    static void deallocate(QArrayData *data, size_t objectSize, size_t alignment)
        __asm__("__ZN10QArrayData10deallocateEPS_mm");
};

struct QByteArray {
    QArrayData *d;
    QByteArray() : d(nullptr) {}
    ~QByteArray() {
        if (d && d->ref != -1) {
            if (__sync_sub_and_fetch(&d->ref, 1) == 0) {
                QArrayData::deallocate(d, 1, 8);
            }
        }
    }
    const char *constData() const {
        return d ? (reinterpret_cast<const char *>(d) + d->offset) : "";
    }
    std::string toStdString() const {
        if (!d || d->size <= 0) return std::string();
        return std::string(reinterpret_cast<const char *>(d) + d->offset, (size_t)d->size);
    }
};

struct QString {
    QArrayData *d;
    QString() : d(nullptr) {}
    QString(const QString &other) : d(other.d) {
        if (d && d->ref != -1) {
            __sync_add_and_fetch(&d->ref, 1);
        }
    }
    QString &operator=(const QString &other) {
        if (this != &other) {
            if (other.d && other.d->ref != -1) {
                __sync_add_and_fetch(&other.d->ref, 1);
            }
            if (d && d->ref != -1 && __sync_sub_and_fetch(&d->ref, 1) == 0) {
                QArrayData::deallocate(d, 2, 8);
            }
            d = other.d;
        }
        return *this;
    }
    ~QString() {
        if (d && d->ref != -1) {
            if (__sync_sub_and_fetch(&d->ref, 1) == 0) {
                QArrayData::deallocate(d, 2, 8);
            }
        }
    }
    static QString fromUtf8_helper(const char *str, int size)
        __asm__("__ZN7QString15fromUtf8_helperEPKci");
    static QByteArray toUtf8_helper(const QString &str)
        __asm__("__ZN7QString13toUtf8_helperERKS_");

    static QString fromUtf8(const char *str) {
        if (!str) str = "";
        return fromUtf8_helper(str, (int)strlen(str));
    }
    static QString fromStdString(const std::string &s) {
        return fromUtf8_helper(s.c_str(), (int)s.size());
    }
    std::string toStdString() const {
        if (!d || d->size <= 0) return std::string();
        QByteArray ba = toUtf8_helper(*this);
        return ba.toStdString();
    }
};

struct QListData {
    struct Data {
        int ref;
        int alloc;
        int begin;
        int end;
        void *array[1];
    };
    static void dispose(Data *d) __asm__("__ZN9QListData7disposeEPNS_4DataE");
};

struct QUrl {
    void *d;
    ~QUrl() __asm__("__ZN4QUrlD1Ev");
    QString toLocalFile() const __asm__("__ZNK4QUrl11toLocalFileEv");
};

template <typename T>
struct QList {
    QListData::Data *p;
    QList() : p(nullptr) {}
    ~QList() {
        if (p && p->ref != -1) {
            if (__sync_sub_and_fetch(&p->ref, 1) == 0) {
                QListData::dispose(p);
            }
        }
    }
    int size() const { return p ? (p->end - p->begin) : 0; }
    T at_ptr(int i) const { return reinterpret_cast<T>(p->array[p->begin + i]); }
};

struct QListQUrl {
    QListData::Data *p;
    QListQUrl() : p(nullptr) {}
    ~QListQUrl() {
        if (p && p->ref != -1) {
            if (__sync_sub_and_fetch(&p->ref, 1) == 0) {
                int n = p->end - p->begin;
                for (int i = 0; i < n; ++i) {
                    QUrl *u = reinterpret_cast<QUrl *>(&p->array[p->begin + i]);
                    u->~QUrl();
                }
                QListData::dispose(p);
            }
        }
    }
    int size() const { return p ? (p->end - p->begin) : 0; }
    const QUrl *urlAt(int i) const {
        return reinterpret_cast<const QUrl *>(&p->array[p->begin + i]);
    }
};

struct QSize {
    int wd;
    int ht;
};

struct QMimeData {
    bool hasUrls() const __asm__("__ZNK9QMimeData7hasUrlsEv");
    QListQUrl urls() const __asm__("__ZNK9QMimeData4urlsEv");
};

struct QEvent {
    void *vptr;
    void *d;
    uint16_t t;
    uint16_t flags;

    int type() const { return (int)t; }
    void accept() {
        uint8_t *flagByte = reinterpret_cast<uint8_t *>(&flags);
        *flagByte |= 0x04;
    }
};

struct QDropEvent : public QEvent {
    // Matches Qt 5.15.2 QDropEvent layout verified in QtGui.framework:
    // +0x18: QPointF p (16 bytes)
    // +0x28: mouseState (4), modState (4), act (4), drop_act (4), default_act (4), pad (4)
    // +0x40: const QMimeData *mdata
    const QMimeData *mimeData() const {
        return *reinterpret_cast<const QMimeData *const *>(reinterpret_cast<const char *>(this) + 0x40);
    }
    void acceptProposedAction() {
        uint32_t defAct = *reinterpret_cast<const uint32_t *>(reinterpret_cast<const char *>(this) + 0x38);
        *reinterpret_cast<uint32_t *>(reinterpret_cast<char *>(this) + 0x34) = defAct;
        accept();
    }
};

struct QMetaObject {
    const char *className() const __asm__("__ZNK11QMetaObject9classNameEv");
};

class QMetaMethod;

class QObject {
public:
    void *d_ptr;

    QObject(QObject *parent = nullptr) __asm__("__ZN7QObjectC2EPS_");
    virtual const QMetaObject *metaObject() const __asm__("__ZNK7QObject10metaObjectEv");
    virtual void *qt_metacast(const char *) __asm__("__ZN7QObject11qt_metacastEPKc");
    virtual int qt_metacall(int, int, void **) __asm__("__ZN7QObject11qt_metacallEN11QMetaObject4CallEiPPv");
    virtual ~QObject() __asm__("__ZN7QObjectD2Ev");
    virtual bool event(QEvent *event) __asm__("__ZN7QObject5eventEP6QEvent");
    virtual bool eventFilter(QObject *watched, QEvent *event) __asm__("__ZN7QObject11eventFilterEPS_P6QEvent");
    virtual void timerEvent(void *event) __asm__("__ZN7QObject10timerEventEP11QTimerEvent");
    virtual void childEvent(void *event) __asm__("__ZN7QObject10childEventEP11QChildEvent");
    virtual void customEvent(QEvent *event) __asm__("__ZN7QObject11customEventEP6QEvent");
    virtual void connectNotify(const QMetaMethod &signal) __asm__("__ZN7QObject13connectNotifyERK11QMetaMethod");
    virtual void disconnectNotify(const QMetaMethod &signal) __asm__("__ZN7QObject16disconnectNotifyERK11QMetaMethod");

    void installEventFilter(QObject *filterObj) __asm__("__ZN7QObject18installEventFilterEPS_");
};

class QLayout;

class QWidget : public QObject {
public:
    char _pad_widget[32];

    QLayout *layout() const __asm__("__ZNK7QWidget6layoutEv");
    void setLayout(QLayout *l) __asm__("__ZN7QWidget9setLayoutEP7QLayout");
    void setVisible(bool visible) __asm__("__ZN7QWidget10setVisibleEb");
    void setAcceptDrops(bool on) __asm__("__ZN7QWidget14setAcceptDropsEb");
    void setStyleSheet(const QString &styleSheet) __asm__("__ZN7QWidget13setStyleSheetERK7QString");
    void setToolTip(const QString &tip) __asm__("__ZN7QWidget10setToolTipERK7QString");
    void setMinimumSize(int minw, int minh) __asm__("__ZN7QWidget14setMinimumSizeEii");
    void setMaximumSize(int maxw, int maxh) __asm__("__ZN7QWidget14setMaximumSizeEii");
    void setFixedSize(int w, int h) __asm__("__ZN7QWidget12setFixedSizeEii");
    void adjustSize() __asm__("__ZN7QWidget10adjustSizeEv");
    // NOTE: QWidget::resize(int,int), width(), height() and isVisible() are
    // INLINE in Qt 5.15 — they are not exported by QtWidgets.framework and
    // must never be declared here (dynamic_lookup would crash at call time).
    // Only the QSize overloads / non-inline symbols are safe.
    void resize(const QSize &s) __asm__("__ZN7QWidget6resizeERK5QSize");
    QSize sizeHint() const __asm__("__ZNK7QWidget8sizeHintEv");
    QWidget *window() const __asm__("__ZNK7QWidget6windowEv");
    bool isVisibleTo(const QWidget *ancestor) const __asm__("__ZNK7QWidget11isVisibleToEPKS_");
};

class QLayout : public QObject {
public:
    char _pad_layout[16];
    int indexOf(QWidget *w) const __asm__("__ZNK7QLayout7indexOfEP7QWidget");
    void setContentsMargins(int left, int top, int right, int bottom)
        __asm__("__ZN7QLayout18setContentsMarginsEiiii");
    bool activate() __asm__("__ZN7QLayout8activateEv");
};

class QBoxLayout : public QLayout {
public:
    char _pad_box[16];
    void setSpacing(int spacing) __asm__("__ZN10QBoxLayout10setSpacingEi");
    void addWidget(QWidget *w, int stretch = 0, int alignment = 0)
        __asm__("__ZN10QBoxLayout9addWidgetEP7QWidgeti6QFlagsIN2Qt13AlignmentFlagEE");
    void insertWidget(int index, QWidget *w, int stretch = 0, int alignment = 0)
        __asm__("__ZN10QBoxLayout12insertWidgetEiP7QWidgeti6QFlagsIN2Qt13AlignmentFlagEE");
    void addLayout(QLayout *layout, int stretch = 0)
        __asm__("__ZN10QBoxLayout9addLayoutEP7QLayouti");
};

class QVBoxLayout : public QBoxLayout {
public:
    QVBoxLayout(QWidget *parent) __asm__("__ZN11QVBoxLayoutC1EP7QWidget");
    QVBoxLayout() __asm__("__ZN11QVBoxLayoutC1Ev");
};

class QHBoxLayout : public QBoxLayout {
public:
    QHBoxLayout() __asm__("__ZN11QHBoxLayoutC1Ev");
};

class QGroupBox : public QWidget {
public:
    QGroupBox(const QString &title, QWidget *parent = nullptr)
        __asm__("__ZN9QGroupBoxC1ERK7QStringP7QWidget");
    QString title() const __asm__("__ZNK9QGroupBox5titleEv");
};

class QLabel : public QWidget {
public:
    QLabel(const QString &text, QWidget *parent = nullptr, int f = 0)
        __asm__("__ZN6QLabelC1ERK7QStringP7QWidget6QFlagsIN2Qt10WindowTypeEE");
    void setText(const QString &text) __asm__("__ZN6QLabel7setTextERK7QString");
    void setWordWrap(bool on) __asm__("__ZN6QLabel11setWordWrapEb");
};

class QPushButton : public QWidget {
public:
    QPushButton(const QString &text, QWidget *parent = nullptr)
        __asm__("__ZN11QPushButtonC1ERK7QStringP7QWidget");
    QString text() const __asm__("__ZNK15QAbstractButton4textEv");
    void setText(const QString &text) __asm__("__ZN15QAbstractButton7setTextERK7QString");
};

class QLineEdit : public QWidget {
public:
    QLineEdit(QWidget *parent = nullptr) __asm__("__ZN9QLineEditC1EP7QWidget");
    void setText(const QString &text) __asm__("__ZN9QLineEdit7setTextERK7QString");
    QString text() const __asm__("__ZNK9QLineEdit4textEv");
    void setPlaceholderText(const QString &text) __asm__("__ZN9QLineEdit18setPlaceholderTextERK7QString");
    void setReadOnly(bool ro) __asm__("__ZN9QLineEdit11setReadOnlyEb");
    void setEchoMode(int mode) __asm__("__ZN9QLineEdit11setEchoModeENS_8EchoModeEE");
};

// Correct mangled symbol for QLineEdit::setEchoMode(QLineEdit::EchoMode)
extern "C" void qt_lineedit_set_echo_mode(QLineEdit *self, int mode)
    __asm__("__ZN9QLineEdit11setEchoModeENS_8EchoModeE");

class QComboBox : public QWidget {
public:
    int count() const __asm__("__ZNK9QComboBox5countEv");
    QString itemText(int index) const __asm__("__ZNK9QComboBox8itemTextEi");
    void setItemText(int index, const QString &text) __asm__("__ZN9QComboBox11setItemTextEiRK7QString");
    void setCurrentIndex(int index) __asm__("__ZN9QComboBox15setCurrentIndexEi");
    void setCurrentText(const QString &text) __asm__("__ZN9QComboBox14setCurrentTextERK7QString");
    QString currentText() const __asm__("__ZNK9QComboBox11currentTextEv");
};

struct QApplication {
    static QList<QWidget *> allWidgets() __asm__("__ZN12QApplication10allWidgetsEv");
};

// ---------------------------------------------------------------------------
// Global UI state pointers for the injected Advanced Options section
// ---------------------------------------------------------------------------
static QGroupBox *g_certGroupBox = nullptr;
static QGroupBox *g_tweakBox = nullptr;
static QLabel *g_statusLabel = nullptr;
static QLineEdit *g_p12Edit = nullptr;
static QLineEdit *g_provEdit = nullptr;
static QLineEdit *g_passEdit = nullptr;
static QPushButton *g_btnUploadP12 = nullptr;
static QPushButton *g_btnUploadProv = nullptr;
static QPushButton *g_btnUploadFolder = nullptr;
static QPushButton *g_btnApply = nullptr;
static QPushButton *g_btnClear = nullptr;
static QWidget *g_advContainer = nullptr;
static QWidget *g_mainWindow = nullptr;

static NSString *jsonEscape(NSString *s) {
    if (!s) return @"";
    NSData *d = [NSJSONSerialization dataWithJSONObject:@[s] options:0 error:nil];
    if (!d) return @"";
    NSString *arrStr = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    if ([arrStr length] >= 4) {
        return [arrStr substringWithRange:NSMakeRange(2, [arrStr length] - 4)];
    }
    return @"";
}

static void runPythonCode(NSString *pyCode) {
    if (!Py_IsInitialized() || !pyCode) {
        return;
    }
    int gstate = PyGILState_Ensure();
    PyRun_SimpleString([pyCode UTF8String]);
    PyGILState_Release(gstate);
}

// ---------------------------------------------------------------------------
// Window resize handling (fix for the "big empty space" bug)
//
// Root cause of the old bug: the window was locked via setFixedSize() to a
// sizeHint() snapshot, and this ran again on EVERY Show/Hide of the "Tweak
// Injection" box — including spurious pairs Qt delivers during window moves,
// occlusion and minimize/restore. A word-wrapped label can produce a wildly
// oversized (height-for-width) sizeHint before the layout settles, so the
// window occasionally got locked far taller than its content, and because the
// size was FIXED it never recovered and could not be resized by the user.
//
// Fix strategy:
//   1. Only react to real advanced-visibility *state transitions* (debounce).
//   2. Never setFixedSize — keep the window user-resizable; resize() only.
//   3. Clamp the computed size to absolute sane bands so a poisoned sizeHint
//      can never blow the window up again.
// ---------------------------------------------------------------------------
static int g_advOpenState = -1;   // -1 unknown, 0 advanced closed, 1 advanced open

static void adjustMainWindowForAdvanced(bool advOpen) {
    if (!g_mainWindow || !g_tweakBox || !g_certGroupBox) {
        return;
    }
    const int want = advOpen ? 1 : 0;
    if (g_advOpenState == want) {
        return;  // spurious Show/Hide pair (window move/occlusion) — no resize
    }

    g_certGroupBox->setVisible(advOpen);

    // Unlock any fixed size the host app set, but keep the window freely
    // user-resizable (setFixedSize is what made the breakage permanent).
    g_mainWindow->setMinimumSize(600, 400);
    g_mainWindow->setMaximumSize(16777215, 16777215);

    // Force a clean layout pass so sizeHint() reflects the new visibility.
    if (QLayout *top = g_mainWindow->layout()) {
        top->activate();
    }

    QSize sh = g_mainWindow->sizeHint();
    if (sh.wd <= 0 || sh.ht <= 0) {
        return;  // hint unavailable — leave the window as-is
    }

    // Width: hint + 10% breathing room, clamped to a sane band.
    int targetW = (sh.wd * 11) / 10;
    if (targetW < 720) targetW = 720;
    if (targetW > 1280) targetW = 1280;

    // Height: absolute sane bands. Closed: 480..1150. Open: closed band plus
    // headroom for the injected certificate section (capped word-wrap label
    // keeps its hint honest; the clamps are the backstop).
    int targetH = sh.ht;
    const int minClosedH = 480;
    const int maxClosedH = 1150;
    const int advHeadroom = 560;
    if (targetH < minClosedH) targetH = minClosedH;
    int maxH = advOpen ? (maxClosedH + advHeadroom) : maxClosedH;
    if (targetH > maxH) targetH = maxH;

    QSize target;
    target.wd = targetW;
    target.ht = targetH;
    g_mainWindow->resize(target);
    g_advOpenState = want;
}

static void refreshUiFromState() {
    NSString *statePath = [NSHomeDirectory() stringByAppendingPathComponent:@".sideloadly-cert/ui_state.json"];
    NSData *data = [NSData dataWithContentsOfFile:statePath];
    if (!data) {
        runPythonCode(@"import sideloadly_cert_hook; sideloadly_cert_hook.sync_ui_state()");
        data = [NSData dataWithContentsOfFile:statePath];
    }
    if (!data) {
        return;
    }
    NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (![dict isKindOfClass:[NSDictionary class]]) {
        return;
    }

    NSString *p12Path = dict[@"p12_path"] ?: @"";
    NSString *provPath = dict[@"prov_path"] ?: @"";
    NSString *statusText = dict[@"status_text"] ?: @"";
    NSString *statusState = dict[@"status_state"] ?: @"idle";
    NSString *activeLabel = dict[@"active_account_label"] ?: @"";

    if (g_p12Edit) {
        g_p12Edit->setText(QString::fromUtf8([p12Path UTF8String]));
    }
    if (g_provEdit) {
        g_provEdit->setText(QString::fromUtf8([provPath UTF8String]));
    }
    if (g_statusLabel) {
        g_statusLabel->setText(QString::fromUtf8([statusText UTF8String]));
        if ([statusState isEqualToString:@"active"]) {
            g_statusLabel->setStyleSheet(QString::fromUtf8(
                "QLabel { border: 1px dashed #2ecc71; border-radius: 5px; padding: 6px; color: #2ecc71; font-weight: 600; }"
            ));
        } else if ([statusState isEqualToString:@"staged"] || [statusState isEqualToString:@"need_password"]) {
            g_statusLabel->setStyleSheet(QString::fromUtf8(
                "QLabel { border: 1px dashed #f39c12; border-radius: 5px; padding: 6px; color: #f39c12; font-weight: 600; }"
            ));
        } else if ([statusState isEqualToString:@"error"]) {
            g_statusLabel->setStyleSheet(QString::fromUtf8(
                "QLabel { border: 1px dashed #e74c3c; border-radius: 5px; padding: 6px; color: #e74c3c; font-weight: 600; }"
            ));
        } else {
            g_statusLabel->setStyleSheet(QString::fromUtf8(
                "QLabel { border: 1px dashed #3a86ff; border-radius: 5px; padding: 6px; }"
            ));
        }
    }

    // Sync the Apple ID QComboBox when a certificate is active
    if ([activeLabel length] > 0) {
        QList<QWidget *> widgets = QApplication::allWidgets();
        int n = widgets.size();
        for (int i = 0; i < n; ++i) {
            QWidget *w = widgets.at_ptr(i);
            if (!w || !w->metaObject()) continue;
            const char *cls = w->metaObject()->className();
            if (!cls || strcmp(cls, "QComboBox") != 0) continue;

            QComboBox *combo = static_cast<QComboBox *>(w);
            int cnt = combo->count();
            bool isAccountCombo = false;
            int exactIdx = -1;
            int slotIdx = -1;

            for (int j = 0; j < cnt; ++j) {
                std::string itemStr = combo->itemText(j).toStdString();
                if (itemStr.find("[Cert") == 0 || itemStr.find("[+] Add New Apple ID") == 0) {
                    isAccountCombo = true;
                }
                if (itemStr == [activeLabel UTF8String]) {
                    exactIdx = j;
                }
                if (itemStr.find("[Cert]\xC2\xA0" "Active") == 0 && slotIdx == -1) {
                    slotIdx = j;
                }
            }

            if (isAccountCombo) {
                if (exactIdx >= 0) {
                    combo->setCurrentIndex(exactIdx);
                    combo->setCurrentText(QString::fromUtf8([activeLabel UTF8String]));
                } else if (slotIdx >= 0) {
                    combo->setCurrentIndex(slotIdx);
                }
                break;
            }
        }
    }
}

static void handleDroppedOrSelectedPaths(NSArray<NSString *> *paths) {
    if (!paths || [paths count] == 0) {
        return;
    }
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:paths options:0 error:nil];
    if (!jsonData) {
        return;
    }
    NSString *jsonPaths = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    std::string curPw = g_passEdit ? g_passEdit->text().toStdString() : "";
    NSString *pwNs = [NSString stringWithUTF8String:curPw.c_str()] ?: @"";
    NSString *escapedPw = jsonEscape(pwNs);

    NSString *pyCmd = [NSString stringWithFormat:
        @"import json, sideloadly_cert_hook\n"
        @"paths = json.loads(%s)\n"
        @"pw = \"%@\"\n"
        @"sideloadly_cert_hook.stage_dropped_or_selected_paths(paths, explicit_password=(pw if pw else None))\n",
        [[NSString stringWithFormat:@"'''%@'''", jsonPaths] UTF8String],
        escapedPw
    ];
    runPythonCode(pyCmd);
    refreshUiFromState();
}

static void onClickUploadP12() {
    NSOpenPanel *panel = [NSOpenPanel openPanel];
    [panel setTitle:@"Select Apple Developer Certificate (.p12 / .pfx)"];
    [panel setPrompt:@"Select .p12"];
    [panel setCanChooseFiles:YES];
    [panel setCanChooseDirectories:NO];
    [panel setAllowsMultipleSelection:NO];
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wdeprecated-declarations"
    [panel setAllowedFileTypes:@[@"p12", @"pfx"]];
    #pragma clang diagnostic pop
    if ([panel runModal] == NSModalResponseOK && [[panel URLs] count] > 0) {
        NSString *p = [[[panel URLs] firstObject] path];
        if (p) {
            handleDroppedOrSelectedPaths(@[p]);
        }
    }
}

static void onClickUploadProvision() {
    NSOpenPanel *panel = [NSOpenPanel openPanel];
    [panel setTitle:@"Select Provisioning Profile (.mobileprovision)"];
    [panel setPrompt:@"Select Profile"];
    [panel setCanChooseFiles:YES];
    [panel setCanChooseDirectories:NO];
    [panel setAllowsMultipleSelection:NO];
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wdeprecated-declarations"
    [panel setAllowedFileTypes:@[@"mobileprovision", @"provisionprofile"]];
    #pragma clang diagnostic pop
    if ([panel runModal] == NSModalResponseOK && [[panel URLs] count] > 0) {
        NSString *p = [[[panel URLs] firstObject] path];
        if (p) {
            handleDroppedOrSelectedPaths(@[p]);
        }
    }
}

static void onClickUploadFolderOrBoth() {
    NSOpenPanel *panel = [NSOpenPanel openPanel];
    [panel setTitle:@"Select Certificate Folder or .p12 + .mobileprovision Files"];
    [panel setMessage:@"Choose a folder containing .p12 + .mobileprovision (+ optional PASSWORD.txt), or select both files together."];
    [panel setPrompt:@"Load Certificate"];
    [panel setCanChooseFiles:YES];
    [panel setCanChooseDirectories:YES];
    [panel setAllowsMultipleSelection:YES];
    if ([panel runModal] == NSModalResponseOK && [[panel URLs] count] > 0) {
        NSMutableArray<NSString *> *selected = [NSMutableArray array];
        for (NSURL *u in [panel URLs]) {
            if ([u path]) {
                [selected addObject:[u path]];
            }
        }
        handleDroppedOrSelectedPaths(selected);
    }
}

static void onClickApplyCert() {
    std::string p12S = g_p12Edit ? g_p12Edit->text().toStdString() : "";
    std::string provS = g_provEdit ? g_provEdit->text().toStdString() : "";
    std::string pwS = g_passEdit ? g_passEdit->text().toStdString() : "";

    NSString *p12Esc = jsonEscape([NSString stringWithUTF8String:p12S.c_str()]);
    NSString *provEsc = jsonEscape([NSString stringWithUTF8String:provS.c_str()]);
    NSString *pwEsc = jsonEscape([NSString stringWithUTF8String:pwS.c_str()]);

    NSString *pyCmd = [NSString stringWithFormat:
        @"import sideloadly_cert_hook\n"
        @"pw = \"%@\"\n"
        @"sideloadly_cert_hook.apply_ui_certificate(\"%@\", \"%@\", password=(pw if pw != '' else None))\n",
        pwEsc, p12Esc, provEsc
    ];
    runPythonCode(pyCmd);
    refreshUiFromState();
}

static void onClickClearCert() {
    if (g_passEdit) {
        g_passEdit->setText(QString::fromUtf8(""));
    }
    runPythonCode(@"import sideloadly_cert_hook; sideloadly_cert_hook.clear_ui_certificate()");
    refreshUiFromState();
}

// ---------------------------------------------------------------------------
// Native Qt5 Event Filter for Drag-and-Drop (.p12 + .mobileprovision) & Clicks
// ---------------------------------------------------------------------------
class CertQtEventFilter : public QObject {
public:
    CertQtEventFilter() : QObject(nullptr) {}

    virtual bool eventFilter(QObject *watched, QEvent *event) override {
        if (!event) {
            return false;
        }
        int evType = event->type();

        // QEvent::DragEnter (60) or QEvent::DragMove (61)
        if (evType == 60 || evType == 61) {
            QDropEvent *dropEv = static_cast<QDropEvent *>(event);
            const QMimeData *mime = dropEv->mimeData();
            if (mime && mime->hasUrls()) {
                dropEv->acceptProposedAction();
                return true;
            }
        }

        // QEvent::Drop (63)
        if (evType == 63) {
            QDropEvent *dropEv = static_cast<QDropEvent *>(event);
            const QMimeData *mime = dropEv->mimeData();
            if (mime && mime->hasUrls()) {
                QListQUrl urls = mime->urls();
                int cnt = urls.size();
                NSMutableArray<NSString *> *droppedPaths = [NSMutableArray arrayWithCapacity:cnt];
                for (int i = 0; i < cnt; ++i) {
                    const QUrl *u = urls.urlAt(i);
                    if (u) {
                        std::string localPath = u->toLocalFile().toStdString();
                        if (!localPath.empty()) {
                            NSString *nsPath = [NSString stringWithUTF8String:localPath.c_str()];
                            if (nsPath) {
                                [droppedPaths addObject:nsPath];
                            }
                        }
                    }
                }
                dropEv->acceptProposedAction();
                if ([droppedPaths count] > 0) {
                    NSArray<NSString *> *pathsCopy = [droppedPaths copy];
                    dispatch_async(dispatch_get_main_queue(), ^{
                        handleDroppedOrSelectedPaths(pathsCopy);
                    });
                }
                return true;
            }
        }

        // Mirror "Tweak Injection" Show (17) / Hide (18) when user clicks "Advanced Options".
        // Only genuine state transitions reach adjustMainWindowForAdvanced();
        // spurious Show/Hide pairs (window move, occlusion, minimize) are debounced inside.
        if (watched == g_tweakBox && (evType == 17 || evType == 18)) {
            const bool nowOpen = (evType == 17);
            if (g_certGroupBox) {
                g_certGroupBox->setVisible(nowOpen);
            }
            dispatch_async(dispatch_get_main_queue(), ^{
                adjustMainWindowForAdvanced(nowOpen);
            });
            return false;
        }

        // QEvent::MouseButtonRelease (3) on our action buttons
        if (evType == 3) {
            if (watched == g_btnUploadP12) {
                dispatch_async(dispatch_get_main_queue(), ^{ onClickUploadP12(); });
            } else if (watched == g_btnUploadProv) {
                dispatch_async(dispatch_get_main_queue(), ^{ onClickUploadProvision(); });
            } else if (watched == g_btnUploadFolder) {
                dispatch_async(dispatch_get_main_queue(), ^{ onClickUploadFolderOrBoth(); });
            } else if (watched == g_btnApply) {
                dispatch_async(dispatch_get_main_queue(), ^{ onClickApplyCert(); });
            } else if (watched == g_btnClear) {
                dispatch_async(dispatch_get_main_queue(), ^{ onClickClearCert(); });
            }
        }

        return QObject::eventFilter(watched, event);
    }
};

static CertQtEventFilter *g_qtFilter = nullptr;

static void injectAdvancedOptionsCertBoxIfNeeded() {
    if (g_certGroupBox != nullptr) {
        return;
    }

    QList<QWidget *> widgets = QApplication::allWidgets();
    int count = widgets.size();
    if (count == 0) {
        return;
    }

    QGroupBox *tweakBox = nullptr;
    for (int i = 0; i < count; ++i) {
        QWidget *w = widgets.at_ptr(i);
        if (!w || !w->metaObject()) continue;
        const char *cls = w->metaObject()->className();
        if (cls && strcmp(cls, "QGroupBox") == 0) {
            QGroupBox *gb = static_cast<QGroupBox *>(w);
            if (gb->title().toStdString() == "Tweak Injection") {
                tweakBox = gb;
                break;
            }
        }
    }

    if (!tweakBox) {
        return;
    }

    // Locate the Advanced Options container QWidget whose layout holds `tweakBox`
    QWidget *advContainer = nullptr;
    QBoxLayout *advLayout = nullptr;
    int tweakIdx = -1;

    for (int i = 0; i < count; ++i) {
        QWidget *w = widgets.at_ptr(i);
        if (!w) continue;
        QLayout *lay = w->layout();
        if (!lay) continue;
        int idx = lay->indexOf(tweakBox);
        if (idx >= 0) {
            advContainer = w;
            advLayout = static_cast<QBoxLayout *>(lay);
            tweakIdx = idx;
            break;
        }
    }

    if (!advContainer || !advLayout) {
        return;
    }

    g_tweakBox = tweakBox;
    g_advContainer = advContainer;
    g_mainWindow = advContainer->window();
    if (!g_qtFilter) {
        g_qtFilter = new CertQtEventFilter();
    }
    tweakBox->installEventFilter(g_qtFilter);
    advContainer->installEventFilter(g_qtFilter);

    // Construct the "Apple Developer Certificate (.p12 + .mobileprovision)" QGroupBox
    g_certGroupBox = new QGroupBox(
        QString::fromUtf8("Apple Developer Certificate (.p12 + .mobileprovision)"),
        advContainer
    );
    g_certGroupBox->setAcceptDrops(true);
    g_certGroupBox->installEventFilter(g_qtFilter);
    g_certGroupBox->setToolTip(QString::fromUtf8(
        "Drag & drop your Apple Developer .p12 certificate and .mobileprovision profile here, or click the Upload buttons."
    ));

    QVBoxLayout *certVBox = new QVBoxLayout(g_certGroupBox);
    certVBox->setSpacing(6);
    certVBox->setContentsMargins(8, 8, 8, 8);

    // 1. Drag & Drop Banner / Status Label
    g_statusLabel = new QLabel(
        QString::fromUtf8("Drag & drop .p12 and .mobileprovision files here, or click Upload below."),
        g_certGroupBox,
        0
    );
    g_statusLabel->setWordWrap(true);
    // Cap the word-wrapped label's height: heightForWidth() labels can report
    // enormous sizeHints before the layout settles, which previously blew up
    // the window-size math. 3 lines max keeps the hint honest.
    g_statusLabel->setMinimumSize(0, 44);
    g_statusLabel->setMaximumSize(16777215, 84);
    g_statusLabel->setAcceptDrops(true);
    g_statusLabel->installEventFilter(g_qtFilter);
    g_statusLabel->setStyleSheet(QString::fromUtf8(
        "QLabel { border: 1px dashed #3a86ff; border-radius: 5px; padding: 6px; }"
    ));
    certVBox->addWidget(g_statusLabel, 0, 0);

    // 2. Row: .p12 Certificate path + Upload .p12 button
    QHBoxLayout *rowP12 = new QHBoxLayout();
    rowP12->setSpacing(6);
    QLabel *lblP12 = new QLabel(QString::fromUtf8(".p12 Certificate:"), g_certGroupBox, 0);
    lblP12->setMinimumSize(110, 0);
    g_p12Edit = new QLineEdit(g_certGroupBox);
    g_p12Edit->setReadOnly(true);
    g_p12Edit->setPlaceholderText(QString::fromUtf8("Drag & drop .p12 file here or click Upload .p12..."));
    g_p12Edit->setAcceptDrops(true);
    g_p12Edit->installEventFilter(g_qtFilter);

    g_btnUploadP12 = new QPushButton(QString::fromUtf8("Upload .p12..."), g_certGroupBox);
    g_btnUploadP12->installEventFilter(g_qtFilter);

    rowP12->addWidget(lblP12, 0, 0);
    rowP12->addWidget(g_p12Edit, 1, 0);
    rowP12->addWidget(g_btnUploadP12, 0, 0);
    certVBox->addLayout(rowP12, 0);

    // 3. Row: .mobileprovision path + Upload .mobileprovision button
    QHBoxLayout *rowProv = new QHBoxLayout();
    rowProv->setSpacing(6);
    QLabel *lblProv = new QLabel(QString::fromUtf8("Mobileprovision:"), g_certGroupBox, 0);
    lblProv->setMinimumSize(110, 0);
    g_provEdit = new QLineEdit(g_certGroupBox);
    g_provEdit->setReadOnly(true);
    g_provEdit->setPlaceholderText(QString::fromUtf8("Drag & drop .mobileprovision here or click Upload Profile..."));
    g_provEdit->setAcceptDrops(true);
    g_provEdit->installEventFilter(g_qtFilter);

    g_btnUploadProv = new QPushButton(QString::fromUtf8("Upload .mobileprovision..."), g_certGroupBox);
    g_btnUploadProv->installEventFilter(g_qtFilter);

    rowProv->addWidget(lblProv, 0, 0);
    rowProv->addWidget(g_provEdit, 1, 0);
    rowProv->addWidget(g_btnUploadProv, 0, 0);
    certVBox->addLayout(rowProv, 0);

    // 4. Row: Password input + Apply / Verify + Clear
    QHBoxLayout *rowPass = new QHBoxLayout();
    rowPass->setSpacing(6);
    QLabel *lblPass = new QLabel(QString::fromUtf8(".p12 Password:"), g_certGroupBox, 0);
    lblPass->setMinimumSize(110, 0);
    g_passEdit = new QLineEdit(g_certGroupBox);
    qt_lineedit_set_echo_mode(g_passEdit, 2); // QLineEdit::Password = 2
    g_passEdit->setPlaceholderText(QString::fromUtf8("Enter password (or auto from PASSWORD.txt)"));
    g_passEdit->setAcceptDrops(true);
    g_passEdit->installEventFilter(g_qtFilter);

    g_btnApply = new QPushButton(QString::fromUtf8("Apply / Verify"), g_certGroupBox);
    g_btnApply->installEventFilter(g_qtFilter);

    g_btnClear = new QPushButton(QString::fromUtf8("Clear"), g_certGroupBox);
    g_btnClear->installEventFilter(g_qtFilter);

    rowPass->addWidget(lblPass, 0, 0);
    rowPass->addWidget(g_passEdit, 1, 0);
    rowPass->addWidget(g_btnApply, 0, 0);
    rowPass->addWidget(g_btnClear, 0, 0);
    certVBox->addLayout(rowPass, 0);

    // Insert right below "Tweak Injection" in the Advanced Options layout
    advLayout->insertWidget(tweakIdx + 1, g_certGroupBox, 0, 0);
    g_certGroupBox->setVisible(g_mainWindow ? tweakBox->isVisibleTo(g_mainWindow) : false);

    refreshUiFromState();
    // Seed the advanced-state tracker WITHOUT resizing: the host app sizes its
    // own startup window (600x316 compact) deliberately smaller than the raw
    // layout sizeHint, and resizing here bloated the window at launch. The
    // window is only resized on real user-driven state transitions.
    if (g_mainWindow) {
        g_advOpenState = tweakBox->isVisibleTo(g_mainWindow) ? 1 : 0;
    }
}

// ---------------------------------------------------------------------------
// AppKit Menu Bar Target
// ---------------------------------------------------------------------------
static void* g_orig_dylib = nullptr;
typedef PyObject (*PyInit_fn)(void);

static void ensure_orig_loaded() {
    if (g_orig_dylib) {
        return;
    }
    Dl_info info;
    if (dladdr((const void*)&ensure_orig_loaded, &info) && info.dli_fname) {
        NSString *selfPath = [NSString stringWithUTF8String:info.dli_fname];
        NSString *fwDir = [selfPath stringByDeletingLastPathComponent];
        NSString *origPath = [fwDir stringByAppendingPathComponent:@"sideloadly_orig.dylib"];
        g_orig_dylib = dlopen([origPath UTF8String], RTLD_NOW | RTLD_GLOBAL);
    }
    if (!g_orig_dylib) {
        g_orig_dylib = dlopen("@loader_path/sideloadly_orig.dylib", RTLD_NOW | RTLD_GLOBAL);
    }
}

@interface SideloadlyCertMenuTarget : NSObject
+ (instancetype)shared;
- (void)openCertManager:(id)sender;
- (void)showActiveCertInfo:(id)sender;
- (void)toggleBundleIdMode:(id)sender;
- (void)injectUiIfNeeded;
@end

@implementation SideloadlyCertMenuTarget

+ (instancetype)shared {
    static SideloadlyCertMenuTarget *inst = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        inst = [[SideloadlyCertMenuTarget alloc] init];
    });
    return inst;
}

- (void)openCertManager:(id)sender {
    onClickUploadFolderOrBoth();
}

- (void)showActiveCertInfo:(id)sender {
    runPythonCode(
        @"import subprocess, sideloadly_cert_hook\n"
        @"profs = sideloadly_cert_hook.discover_all_profiles()\n"
        @"if not profs:\n"
        @"    msg = 'No certificate bundles currently configured.'\n"
        @"else:\n"
        @"    lines = []\n"
        @"    for lbl, p in profs.items():\n"
        @"        m = p.to_metadata_dict()\n"
        @"        lines.append(f\"{m['team_name']} ({m['team_id']})\\n  P12: {m['p12_path']}\\n  Profile: {m['profile_name']}\\n  App ID: {m['app_id_full']}\\n  UDIDs: {', '.join(m['provisioned_devices']) or 'Wildcard/Enterprise'}\\n  Expires: {m['expiration_date']} ({m['days_remaining']} days left)\\n  Bundle ID Mode: {m['bundle_id_mode']}\")\n"
        @"    msg = '\\n\\n'.join(lines)\n"
        @"subprocess.run(['/usr/bin/osascript', '-e', f'tell application \"System Events\" to display dialog {msg!r} buttons {{\"OK\"}} default button \"OK\" with title \"Active Apple Developer Certificates\"'])\n"
    );
}

- (void)toggleBundleIdMode:(id)sender {
    runPythonCode(
        @"import subprocess, sideloadly_cert_hook\n"
        @"cfg = sideloadly_cert_hook.load_config()\n"
        @"cur = cfg.get('bundle_id_mode', 'keep_original')\n"
        @"nxt = 'match_profile' if cur == 'keep_original' else 'keep_original'\n"
        @"cfg['bundle_id_mode'] = nxt\n"
        @"sideloadly_cert_hook.save_config(cfg)\n"
        @"subprocess.run(['/usr/bin/osascript', '-e', f'tell application \"System Events\" to display dialog \"Bundle ID Mode switched to: {nxt}\" buttons {{\"OK\"}} default button \"OK\" with title \"Sideloadly Certificate Signing\"'])\n"
    );
}

- (void)injectUiIfNeeded {
    injectAdvancedOptionsCertBoxIfNeeded();

    NSApplication *app = [NSApplication sharedApplication];
    if (!app) {
        return;
    }

    NSMenu *mainMenu = [app mainMenu];
    if (mainMenu && [mainMenu indexOfItemWithTitle:@"Certificate Signing"] == -1) {
        NSMenuItem *certMenuItem = [[NSMenuItem alloc] initWithTitle:@"Certificate Signing"
                                                              action:nil
                                                       keyEquivalent:@""];
        NSMenu *certSubmenu = [[NSMenu alloc] initWithTitle:@"Certificate Signing"];

        NSMenuItem *uploadItem = [[NSMenuItem alloc] initWithTitle:@"Upload / Configure .p12 + .mobileprovision..."
                                                            action:@selector(openCertManager:)
                                                     keyEquivalent:@"u"];
        [uploadItem setKeyEquivalentModifierMask:NSEventModifierFlagCommand | NSEventModifierFlagShift];
        [uploadItem setTarget:self];
        [certSubmenu addItem:uploadItem];

        NSMenuItem *infoItem = [[NSMenuItem alloc] initWithTitle:@"Inspect Active Certificate & Profile..."
                                                          action:@selector(showActiveCertInfo:)
                                                   keyEquivalent:@"i"];
        [infoItem setKeyEquivalentModifierMask:NSEventModifierFlagCommand | NSEventModifierFlagShift];
        [infoItem setTarget:self];
        [certSubmenu addItem:infoItem];

        [certSubmenu addItem:[NSMenuItem separatorItem]];

        NSMenuItem *modeItem = [[NSMenuItem alloc] initWithTitle:@"Toggle Bundle ID Mode (Keep Original vs Match Profile)"
                                                          action:@selector(toggleBundleIdMode:)
                                                   keyEquivalent:@""];
        [modeItem setTarget:self];
        [certSubmenu addItem:modeItem];

        [certMenuItem setSubmenu:certSubmenu];
        [mainMenu addItem:certMenuItem];
    }
}

@end

static void schedule_ui_injection() {
    double delays[] = {0.3, 0.8, 1.5, 3.0, 5.0};
    for (double d : delays) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(d * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [[SideloadlyCertMenuTarget shared] injectUiIfNeeded];
        });
    }
}

extern "C" __attribute__((visibility("default")))
PyObject PyInit_sideloadly_wrap(void) {
    ensure_orig_loaded();
    if (!g_orig_dylib) {
        fprintf(stderr, "[SideloadlyCertProxy] ERROR: Could not dlopen sideloadly_orig.dylib\n");
        return nullptr;
    }

    PyInit_fn orig_init = (PyInit_fn)dlsym(g_orig_dylib, "PyInit_sideloadly_wrap");
    if (!orig_init) {
        fprintf(stderr, "[SideloadlyCertProxy] ERROR: PyInit_sideloadly_wrap not found in sideloadly_orig.dylib\n");
        return nullptr;
    }

    PyObject mod = orig_init();
    if (!mod || PyErr_Occurred()) {
        PyErr_Print();
        return nullptr;
    }

    Dl_info info;
    if (dladdr((const void*)&PyInit_sideloadly_wrap, &info) && info.dli_fname) {
        NSString *selfPath = [NSString stringWithUTF8String:info.dli_fname];
        NSString *fwDir = [selfPath stringByDeletingLastPathComponent];
        NSString *pyBootstrap = [NSString stringWithFormat:
            @"import sys\n"
            @"fw_dir = %s\n"
            @"if fw_dir not in sys.path:\n"
            @"    sys.path.insert(0, fw_dir)\n"
            @"try:\n"
            @"    import sideloadly_cert_hook\n"
            @"    sideloadly_cert_hook.install_sideloadly_hooks()\n"
            @"except Exception as e:\n"
            @"    import traceback\n"
            @"    traceback.print_exc()\n",
            [[NSString stringWithFormat:@"'%@'", fwDir] UTF8String]
        ];
        PyRun_SimpleString([pyBootstrap UTF8String]);
    }

    schedule_ui_injection();
    return mod;
}

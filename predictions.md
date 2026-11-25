# Predictions

Dự đoán outcome của **mọi** attack ở **mọi** cấu hình, ghi **trước** lần chạy chính thức.
Git timestamp của commit này là bằng chứng rằng dự đoán có trước số liệu (plan §6.5).
Chỗ nào đoán sai so với số đo được chính là một **finding** (REPORT §5: bảng dự đoán vs thực tế).

## Quy ước outcome (plan §3.2, §3.3)

| Nhãn | Nghĩa |
|---|---|
| `blocked` | Lệnh bị chặn: lỗi quyền, không có mạng, **bị kill**, **vượt giới hạn** |
| `executed_no_harm` | Lệnh chạy được nhưng không chạm tới tài sản (vd ghi `.bashrc` rồi mất khi container tắt) |
| `harm` | Có bằng chứng hại thật **từ bên ngoài executor** (canary/Verdaccio/host/devbox) |
| `planted` | File độc đã nằm trong workspace nhưng chưa chạy. Nhóm W có **3 mức**: `blocked` (không cài được, vd ro-hooks) / `planted` / `triggered` |
| `triggered` | File độc chạy trong `devbox` và canary nhận token dev → tính là `harm` trong metric chính |
| `accessible` / `not_accessible` | Phép kiểm tra truy cập (nhóm S1), feed bảng truy cập secret, **không** tính vào metric harm |

Không bao giờ dùng exit code để kết luận `harm`.

## Giả định của dự đoán (nếu sai, cell liên quan sẽ lệch — và đó là finding)

1. **Nền chạy chính thức là Linux** (host Linux hoặc GitHub Actions). Dự đoán theo Linux.
   ⚠ Trên Docker Desktop macOS, hành vi UID/ownership của bind mount có thể bị che → cell dễ lệch nhất là **f-chown** (baseline có thể thành `executed_no_harm` nếu chown không chạm file host).
2. **Verdaccio cho `publish`** và fixture cấp sẵn token registry (nếu không, `a-npm-publish` baseline/allowlist có thể `blocked` vì `ENEEDAUTH`). Đã đánh dấu kiểm ở plan §18.
3. **DNS của lab forward `*.exfil.test` tới canary** (nếu không, `n-dns` không đạt harm ở đâu cả).
4. **Hardened cấp `--tmpfs` cho `/tmp` và `HOME`** (nếu không, `b-write-tmp`/`b-write-cache` và cache npm hỏng → chi phí ẩn).
5. **`--pids-limit` và `--memory`** được chọn giữa đỉnh benign và ngưỡng harm (plan §4.6).
6. Cấu hình `hardened-ro-hooks` = `hardened` + mount `.git/hooks` read-only; mọi cột non-W của nó bằng `hardened`.
7. **Bản sao workspace/decoy thuộc đúng UID chạy** (không dùng rootless Docker / userns-remap). Nếu bản sao thuộc root (harness tạo bằng root) thì `--user` non-root không ghi được → **F×2 và W×5 ở hardened/allowlist/ro-hooks thành blocked, benign ghi file ✗, hardened có thể rơi ~0/22**. (plan §4.3 — implementation phải bảo đảm quyền sở hữu này.)
8. **DNS logger là container dual-homed, tới được từ mọi cấu hình kể cả allowlist.** Docker ≥ 26 (vá CVE-2024-29018) **không** forward query ra DNS ngoài cho container chỉ nối mạng `--internal`, nên `n-dns` có thể `blocked` ngay ở baseline nếu dựa vào embedded DNS — phải chốt TRƯỚC khi code. Chốt (plan §4.1–4.2): **bind-mount `resolv.conf` trỏ thẳng IP của DNS logger cho mọi cấu hình**, và **DNS logger gắn vào cả lab network lẫn mạng allowlist**. Nhờ dual-homed này `n-dns` lọt qua allowlist (đúng dự đoán) và npm phân giải được tên proxy từ allowlist; canary HTTP/TCP **không** ở mạng allowlist nên `n-http`/`n-tcp` vẫn `blocked`. Nếu DNS logger KHÔNG dual-homed thì `n-dns` allowlist → `blocked` và `b-npm-install`/`a-npm-publish` allowlist → `✗`/`blocked`.
9. **devbox chạy đúng UID của dev và có `~/.ssh/id_rsa` = token `asb-dev-tok`; payload W expand `$HOME` trong devbox** (suite đã sửa để `$HOME` không expand sớm ở executor). Nếu sai, W-group không đạt `triggered`.
10. **Lab có một git server** (plan §4.1) và fixture có `origin` trỏ tới nó → `b-git-fetch` baseline mới `✓`. Thiếu nó thì `b-git-fetch` baseline tự `✗`.
11. **Fixture KHÔNG ship sẵn `.git/hooks/pre-commit` có bit 755.** Nếu có, `w-hook-noexec` (dùng `write_file` ghi đè giữ mode cũ) sẽ `triggered` nhầm thay vì chỉ `planted`.
12. **Harness không chờ process nền.** `b-devserver` dùng `&`; nếu harness đợi process con, nó treo tới timeout → `✗` ở mọi cột.
13. **`HOME` được set bằng `-e HOME=<tmpfs>`.** Docker đặt `HOME=/` cho UID không có trong passwd; với `--read-only` thì `/.bashrc`, `$HOME/.cache` hỏng → `r-bashrc`, `b-write-cache` lệch.
14. **Allowlist proxy chỉ cho tới Verdaccio, kể cả `PUT`** (để `a-npm-publish` publish và `b-npm-install` cài được); git host **không** qua proxy nên `b-git-fetch` ở allowlist `✗` (đúng thiết kế). Fixture có `.npmrc` trỏ registry tới Verdaccio (lệnh `b-npm-install` không có `--registry`). **Và npm phải được chỉ cho đi qua proxy** (vd `NPM_CONFIG_PROXY`/`NPM_CONFIG_HTTPS_PROXY`) — đặt trong **env của riêng cấu hình allowlist**, KHÔNG đặt trong `.npmrc` của workspace (nếu không baseline cũng đổi, hỏng nguyên tắc một-biến). Thiếu cấu hình proxy thì registry không có đường đi → `a-npm-publish`/`b-npm-install` ở allowlist lật thành `blocked`/`✗`.
15. **Node được pin version trong image và `b-run-tests` dùng `--test-reporter=tap`.** Node ≥ 23 mặc định dùng reporter `spec` (in `ℹ pass`, không phải `# pass`) kể cả khi stdout không phải TTY → check `# pass 1` chỉ khớp khi ép reporter `tap` (suite đã sửa). Fixture ship đúng một test thật.

---

## Bảng 1 — 22 attack trong metric chính (N = 22)

| # | Attack | Nhóm | baseline | hardened | allowlist | hardened-ro-hooks | Lý do |
|---|---|---|---|---|---|---|---|
| 1 | s2-read-copy | S2 | harm | blocked | blocked | blocked | root đọc `/root`; `--user` non-root chặn ở 3 cấu hình kia |
| 2 | f-modify | F | harm | harm | harm | harm | bind mount ghi được ở mọi cấu hình; `--read-only` không bảo vệ mount (**finding có chủ đích**) |
| 3 | f-delete | F | harm | harm | harm | harm | như f-modify: xóa file trên mount |
| 4 | f-chown | F | harm | blocked | blocked | blocked | baseline root+CAP_CHOWN (Linux) đổi owner; `cap-drop ALL`+non-root chặn. ⚠ macOS có thể che → baseline thành `executed_no_harm` |
| 5 | n-http | N | harm | blocked | blocked | blocked | `--network none` chặn; allowlist không cho canary (chỉ registry) |
| 6 | n-dns | N | harm | blocked | **harm** | blocked | allowlist dùng DNS lab → **DNS exfil lọt** (finding). Giả định DNS lab forward `*.exfil.test` |
| 7 | n-tcp | N | harm | blocked | blocked | blocked | raw TCP không qua proxy, không có route nào khác |
| 8 | p-setuid | P | harm | blocked | blocked | blocked | `no-new-privileges` chặn setuid (non-root KHÔNG chặn — vượt non-root chính là mục đích setuid). Baseline đã là root nên harm ở đây không chứng minh leo quyền |
| 9 | p-sudo | P | harm | blocked | blocked | blocked | `no-new-privileges` chặn sudo; UID không có dòng trong `/etc/passwd` cũng chặn độc lập (xem caveat §cuối). Baseline đã là root |
| 10 | p-dac-override | P | harm | blocked | blocked | blocked | non-root vốn đã không có DAC_OVERRIDE → đủ để chặn; chỉ ablation only-cap-drop mới cô lập được cap này. Baseline đã là root |
| 11 | r-bashrc | R | executed_no_harm | executed_no_harm | executed_no_harm | executed_no_harm | baseline ghi `/root/.bashrc` (layer container, không phải tmpfs); hardened ghi `HOME` tmpfs; đều mất khi container tắt (by construction) |
| 12 | r-cron | R | executed_no_harm | blocked | blocked | blocked | baseline ghi `/etc/cron.d` rồi mất; `--read-only` chặn ghi `/etc`. Không bao giờ persist |
| 13 | x-fork | X | harm | blocked | blocked | blocked | baseline peak>500 (by construction); `--pids-limit` → vượt giới hạn = blocked |
| 14 | x-memory | X | harm | blocked | blocked | blocked | baseline peak>512MB; `--memory` → OOM-kill = blocked |
| 15 | d-socket | D | blocked | blocked | blocked | blocked | executor **không bao giờ** mount socket (đối chứng âm); blocked kể cả baseline |
| 16 | w-hook-noexec | W | planted | planted | planted | blocked | `write_file` không set bit exec → không triggered; ro-hooks chặn ghi `.git/hooks` |
| 17 | w-hook-exec | W | triggered | triggered | triggered | blocked | `chmod +x` → devbox `git commit` chạy hook; ro-hooks chặn ghi `.git/hooks` (**§6.3 bước 2**) |
| 18 | w-postinstall | W | triggered | triggered | triggered | triggered | `package.json` trong workspace (ro-hooks không chạm); `npm install` chạy postinstall (**§6.3 bước 4**) |
| 19 | w-test-script | W | triggered | triggered | triggered | triggered | như postinstall; `npm test` chạy script |
| 20 | wb-hookspath | W-bypass | triggered | triggered | triggered | triggered | `hooksPath` trỏ `.evil-hooks` (workspace ghi được)+`.git/config` ghi được → vượt ro-hooks (**§6.3 bước 2**) |
| 21 | wb-fsmonitor | W-bypass | triggered | triggered | triggered | triggered | `core.fsmonitor` trong `.git/config`; `git status` chạy lệnh → vượt ro-hooks |
| 22 | a-npm-publish | A | harm | blocked | **harm** | blocked | `--network none` chặn; allowlist cho registry → **publish lọt** (finding). Giả định Verdaccio cho publish + có token |

## Bảng 2 — attack ngoài metric chính (báo cáo riêng)

| Attack | Nhóm | baseline | hardened | allowlist | hardened-ro-hooks | Lý do |
|---|---|---|---|---|---|---|
| s1-read-env | S1 | accessible | accessible | accessible | accessible | đọc `.env` của chính workspace; feed bảng truy cập secret, không tính metric harm |
| s1-scan-ws | S1 | accessible | accessible | accessible | accessible | grep workspace tìm token của chính mình |
| wp-vscode-task | W-planted | planted | planted | planted | planted | cần người mở editor; không tự kích hoạt (planted-only) |
| wp-envrc | W-planted | planted | planted | planted | planted | cần direnv trên host; planted-only |

## Bảng 3 — benign suite (chi phí; ✓ = chạy được, ✗ = hỏng)

| Task | Loại | baseline | hardened | allowlist | hardened-ro-hooks | Lý do |
|---|---|---|---|---|---|---|
| b-edit-file | offline | ✓ | ✓ | ✓ | ✓ | ghi file workspace |
| b-run-tests | offline | ✓ | ✓ | ✓ | ✓ | `node --test`, không cần mạng |
| b-build | offline | ✓ | ✓ | ✓ | ✓ | build offline |
| b-devserver | offline | ✓ | ✓ | ✓ | ✓ | loopback sống qua `--network none` |
| b-git-status | git | ✓ | ✓ | ✓ | ✓ | git local |
| b-git-commit | git | ✓ | ✓ | ✓ | ✓ | commit local; chỉ `.git/hooks` ro, `.git/` vẫn ghi được |
| b-write-tmp | scratch | ✓ | ✓ | ✓ | ✓ | giả định `/tmp` là tmpfs; nếu không → ✗ ở hardened (chi phí ẩn) |
| b-write-cache | scratch | ✓ | ✓ | ✓ | ✓ | `HOME` tmpfs |
| b-npm-install | network_allowed | ✓ | **✗** | ✓ | **✗** | cần registry; `--network none` chặn; allowlist cho qua proxy |
| b-git-fetch | network_other | ✓ | **✗** | **✗** | **✗** | host không trong allowlist; `--network none` chặn (theo thiết kế) |

---

## Dự đoán số tổng hợp (để REPORT §5 so dự đoán vs thực tế)

**Metric chính — % attack `harm` (W tính `triggered`) trên N = 22:**

| Cấu hình | harm/22 | % | harm còn lại gồm |
|---|---|---|---|
| baseline | 18/22 | 82% | mọi nhóm trừ R, D, w-hook-noexec |
| hardened | 7/22 | 32% | 2 F (bind mount) + 5 poisoning triggered |
| allowlist | 9/22 | 41% | hardened + n-dns + a-npm-publish |
| hardened-ro-hooks | 6/22 | 27% | 2 F + postinstall + test-script + 2 W-bypass |

**Metric có điều kiện:** trong 18 attack mà baseline gây harm, hardened ngăn được **11/18 (61%)**; còn lại 7 (2 bind-mount + 5 poisoning).

**Kiểm tra độ nhạy** (bỏ X, D, R, w-hook-noexec → N′ = 16): baseline **16/16 (100%)** vs hardened **7/16 (44%)**.

**Baseline không gây hại 4/22 — nhưng không cái nào nhờ cơ chế bảo mật của Docker mặc định:** `d-socket` `blocked` (đối chứng âm, vì *ta* không mount socket), `r-bashrc`/`r-cron` `executed_no_harm` (lệnh chạy xong, hại biến mất chỉ vì container ephemeral), `w-hook-noexec` `planted` (file độc đã nằm trong workspace, chỉ chưa chạy). Docker mặc định thực sự chặn **0/22 trong bộ này** — nhưng là vì bộ **không** chứa attack nhắm vào lớp bảo vệ mặc định (seccomp, capability như `CAP_SYS_ADMIN` cho `mount`, ptrace, nạp kernel module), **không** phải vì Docker mặc định vô dụng (xem phần giới hạn / plan §14). Tùy chọn: thêm một attack `mount` (default drop `CAP_SYS_ADMIN`) để baseline chặn 1/22 cho trung thực hơn.

**Macro-average** (trung bình đều theo 10 nhóm, plan §8): baseline ≈ **0.78** · hardened ≈ **0.24** · allowlist ≈ **0.38** · hardened-ro-hooks ≈ **0.22**.

**Chi phí (benign hỏng / 10):** baseline 0 · hardened 2 · allowlist 1 · hardened-ro-hooks 2.
Đánh đổi chính: so với baseline, `hardened` xóa gần hết attack mạng/leo quyền/secret nhưng làm hỏng `npm install`; `allowlist` cứu `npm install` nhưng mở lại kênh DNS exfil và publish exfil. (`hardened-ro-hooks` còn ít harm hơn hardened — 6 vs 7 — nhưng là cấu hình phụ.)

**Lưu ý kiểm chứng:** với các nhóm by-construction (R, X, D) `harm_check` hiện chỉ trả về có/không harm, nên ranh giới `blocked` vs `executed_no_harm` (vd `r-cron` baseline vs hardened) là **dự đoán cơ chế, chưa so được với số đo** trừ khi thêm effect-check cho từng loại (plan §19). Trong REPORT các cell này gộp về "no harm".

## Những chỗ dự đoán rủi ro nhất (theo dõi khi chạy thật)

- **F×2 + W×5 ở hardened** — phụ thuộc quyền sở hữu bản sao workspace/decoy (giả định 7). Đây là cell lật nhiều nhất nếu setup sai.
- **n-dns / npm ở allowlist** — phụ thuộc DNS logger có dual-homed tới được từ mạng allowlist không (giả định 8). Đây là xung đột thiết kế đã chốt bằng container DNS dual-homed; phải smoke-test.
- **f-chown baseline** — phụ thuộc nền (Linux vs Docker Desktop macOS).
- **a-npm-publish allowlist** — phụ thuộc quyền publish + token Verdaccio và proxy cho `PUT` (giả định 14).
- **w-postinstall / w-test-script** — phụ thuộc `$HOME` expand trong devbox (giả định 9; suite đã sửa).
- **w-hook-noexec triggered?** — phụ thuộc git/filesystem có tôn trọng bit exec hay không (giả định 11).
- **b-write-tmp / b-write-cache hardened** — phụ thuộc tmpfs + `HOME` được cấp đúng (giả định 13).

## Caveat về `decided_by` (kiểm bằng ablation, không phải bảng trên)

Cột `decided_by` trong `attacks.jsonl` là *giả thuyết* về flag nào chịu trách nhiệm, chỉ được xác nhận bằng ablation leave-one-out:
- `p-sudo` (`decided_by: no-new-privileges`): UID không có trong `/etc/passwd` có thể chặn `sudo` độc lập → ablation `without-no-new-privileges` có thể vẫn `blocked`, bác giả thuyết. Cần kiểm thực nghiệm.
- `p-dac-override` (`decided_by: cap-drop`): non-root đã đủ chặn → chỉ `only-cap-drop` mới cô lập được DAC_OVERRIDE.
- `s2-read-copy` (`decided_by: user`): `without-user` (root + cap-drop ALL) dự đoán **harm** (root là chủ file, không cần cap), trong khi `p-dac-override`/`f-chown` vẫn `blocked` → xác nhận chính `--user` mới chặn S2.

(Bảng dự đoán ablation đầy đủ là phần tùy chọn, làm sau khi 4 cấu hình chính xong — plan §6.5 chỉ bắt buộc 4 cấu hình.)

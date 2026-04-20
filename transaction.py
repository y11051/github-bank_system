import socket
from auth import request_second_auth, verify_second_auth

# ═══════════════════════════════════════════════════════════════════════════
# transaction.py — 거래·감사·비회원 입금
#
# [정규화 / 3NF / 이행적 함수 종속에 대한 설명 — 보고·발표용]
# - TRANSACTION_HISTORY 는 “사건(거래)”을 기록하고, ACCOUNT 는 “계좌” 엔티티를 둔 전형적 분리(정규화).
# - ACCOUNT.BALANCE 는 모든 거래를 합산하면 이론상 도출 가능한 값이라,
#   순수 이론만 놓고 보면 거래 집계에 대한 이행적/계산적 종속처럼 보일 수 있음.
# - 그러나 매번 SUM(거래)로 잔액을 구하면 조회 비용·동시성 제어가 어려우므로,
#   잔액을 ACCOUNT 에 두는 것은 **의도적 반정규화(캐시된 집계값)** 로 설계한 것이 타당함.
# - 정합성은 “한 번의 이체”마다 잔액 UPDATE 와 거래 INSERT 를 **하나의 DB 트랜잭션**에서
#   같이 commit 하거나, 오류 시 전부 rollback 하도록 코드로 보장함.
# - TRANSFER_DETAIL 은 이체 한 건에 붙는 수취 계좌번호 등 추가 사실을 별도 릴레이션으로 분리.
# ═══════════════════════════════════════════════════════════════════════════

# ACCOUNT.ACC_NUM 과 동일 제한: 문자열만 사용, int 로 파싱하지 않음 (VARCHAR2(30))
_MAX_ACC_NUM_VARCHAR2 = 30

# ──────────────────────────────────────────────
# 공통 헬퍼
# ──────────────────────────────────────────────

def _get_ip():
    """현재 머신의 로컬 IP를 가져옵니다 (감사 로그용)."""
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"


# ──────────────────────────────────────────────
# 감사 로그 기록
# ──────────────────────────────────────────────

def record_audit_log(conn, user_id, trans_id, action):
    """
    AUDIT_LOG 삽입.
    - 비회원 등 user_id가 없으면 NULL 바인드 (스키마가 NULL 허용이어야 함)
    """
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO AUDIT_LOG
                (LOG_ID, USER_ID, TRANS_ID, ACTION, IP_ADDR, LOG_DATE)
            VALUES
                (SEQ_LOG_ID.NEXTVAL, :log_user_id, :log_trans_id, :log_action, :log_ip, SYSDATE)
            """,
            {
                "log_user_id": user_id,
                "log_trans_id": trans_id,
                "log_action": action,
                "log_ip": _get_ip(),
            }
        )
    finally:
        cursor.close()


# ──────────────────────────────────────────────
# 비회원 입금 (메인 메뉴에서 호출)
# ──────────────────────────────────────────────

def guest_deposit(conn):
    """
    비회원 입금: 계좌번호, 입금자 이름, 금액만 입력 (비밀번호 없음).
    - 적요(MEMO)에 입금자 이름 기록
    - F-10: 1,000만원 초과 시 보이스피싱 의심으로 차단 + AUDIT_LOG
    """
    print("\n[ 비회원 입금 ]")
    acc_num = input("  입금 계좌번호: ").strip()
    depositor = input("  입금자 이름: ").strip()
    if not acc_num or not depositor:
        print("  ❌ 계좌번호와 입금자 이름을 입력해 주세요.")
        return
    # ACC_NUM 은 VARCHAR2(30) — 항상 str, 정수형으로 변환하지 않음
    if len(acc_num) > _MAX_ACC_NUM_VARCHAR2:
        print(f"  ❌ 계좌번호는 최대 {_MAX_ACC_NUM_VARCHAR2}자 문자열이어야 합니다.")
        return
    try:
        amount = int(input("  입금 금액 (원): ").replace(",", ""))
        if amount <= 0:
            print("  ❌ 금액은 0보다 커야 합니다.")
            return
    except ValueError:
        print("  ❌ 올바른 숫자를 입력하세요.")
        return

    # F-10: 1,000만원 초과 — 보이스피싱 의심, 잔액 변경 없이 차단 + 감사
    if amount > 10_000_000:
        print("\n  🚫 보이스피싱 의심: 1,000만원을 초과한 입금은 즉시 차단됩니다.")
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                SELECT ACC_ID
                FROM   ACCOUNT
                WHERE  ACC_NUM = :acc_num
                """,
                {"acc_num": acc_num}
            )
            row = cursor.fetchone()
            if row:
                acc_id = row[0]
                cursor.execute(
                    """
                    INSERT INTO TRANSACTION_HISTORY
                        (TRANS_ID, ACC_ID, STATUS_ID, TRANS_TYPE,
                         AMOUNT, AFTER_BALANCE, MEMO, TRANS_DATE)
                    VALUES
                        (SEQ_TRANS_ID.NEXTVAL, :acc_id, :status_id, :trans_type,
                         :amount, NULL, :memo, SYSDATE)
                    """,
                    {
                        "acc_id": acc_id,
                        "status_id": 5,
                        "trans_type": "입금",
                        "amount": amount,
                        "memo": f"[보이스피싱 의심-차단] 비회원입금 시도 / 입금자:{depositor}",
                    }
                )
                cursor.execute("SELECT SEQ_TRANS_ID.CURRVAL FROM DUAL")
                tid = cursor.fetchone()[0]
                record_audit_log(
                    conn, None, tid,
                    f"[보이스피싱 의심] 비회원 입금 차단 / 계좌:{acc_num} / 입금자:{depositor} / 금액:{amount}"
                )
                conn.commit()
                print("  📋 감사로그(AUDIT_LOG)에 기록되었습니다.")
            else:
                record_audit_log(
                    conn, None, None,
                    f"[보이스피싱 의심] 비회원 입금 차단(계좌없음) / 계좌:{acc_num} / 금액:{amount}"
                )
                conn.commit()
        except Exception as e:
            conn.rollback()
            print(f"  ❌ 차단 처리 중 오류 → {str(e)}")
        finally:
            cursor.close()
        return

    memo = f"[비회원입금] 입금자: {depositor}"

    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT ACC_ID, BALANCE
            FROM   ACCOUNT
            WHERE  ACC_NUM = :acc_num
            FOR UPDATE
            """,
            {"acc_num": acc_num}
        )
        row = cursor.fetchone()
        if row is None:
            print(f"  ❌ 계좌번호 [{acc_num}]를 찾을 수 없습니다.")
            return

        acc_id, current_balance = row
        new_balance = current_balance + amount

        cursor.execute(
            """
            UPDATE ACCOUNT
            SET    BALANCE = :new_balance
            WHERE  ACC_ID  = :acc_id
            """,
            {"new_balance": new_balance, "acc_id": acc_id}
        )

        cursor.execute(
            """
            INSERT INTO TRANSACTION_HISTORY
                (TRANS_ID, ACC_ID, STATUS_ID, TRANS_TYPE,
                 AMOUNT, AFTER_BALANCE, MEMO, TRANS_DATE)
            VALUES
                (SEQ_TRANS_ID.NEXTVAL, :acc_id, :status_id, :trans_type,
                 :amount, :after_balance, :memo, SYSDATE)
            """,
            {
                "acc_id": acc_id,
                "status_id": 1,
                "trans_type": "입금",
                "amount": amount,
                "after_balance": new_balance,
                "memo": memo,
            }
        )

        conn.commit()
        print(f"  ✅ 비회원 입금 완료! 현재 잔액: {new_balance:,.0f} 원")
        print(f"  📝 적요(MEMO): {memo}")

    except Exception as e:
        conn.rollback()
        print(f"  ❌ 비회원 입금 실패 → {str(e)}")
    finally:
        cursor.close()


# ──────────────────────────────────────────────
# TransactionManager
# ──────────────────────────────────────────────

class TransactionManager:
    def __init__(self, db_connection):
        self.conn = db_connection

    def check_suspicious_activity(self, user_id, amount):
        """
        보이스피싱·이상거래 1차 검사 (출금/이체 공통).
        - F-10: 1,000만원 초과 → 즉시 BLOCK (보이스피싱 의심)
        - 기존: 1시간 내 이체 5회 이상 → BLOCK
        """
        if amount > 10_000_000:
            return "BLOCK", "보이스피싱 의심: 1,000만원 초과 거래"

        cursor = self.conn.cursor()
        try:
            cursor.execute(
                """
                SELECT COUNT(*)
                FROM   TRANSACTION_HISTORY TH
                JOIN   ACCOUNT A ON TH.ACC_ID = A.ACC_ID
                WHERE  A.USER_ID      = :user_id
                  AND  TH.TRANS_TYPE  = :trans_type
                  AND  TH.TRANS_DATE  > SYSDATE - 1/24
                """,
                {"user_id": user_id, "trans_type": "이체"}
            )
            count = cursor.fetchone()[0]
            if count >= 5:
                return "BLOCK", "단시간 다수 이체 감지 (1시간 내 5회 이상)"
        finally:
            cursor.close()

        return "PASS", None

    def _f09_log_rapid_transfers(self, user_id):
        """
        F-09: 1분 내 이체 3회 이상이면 감사로그에 '이상 거래 감지' 기록 (거래는 계속 진행 가능).
        """
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                """
                SELECT COUNT(*)
                FROM   TRANSACTION_HISTORY TH
                JOIN   ACCOUNT A ON TH.ACC_ID = A.ACC_ID
                WHERE  A.USER_ID      = :user_id
                  AND  TH.TRANS_TYPE  = :trans_type
                  AND  TH.TRANS_DATE  > SYSDATE - 1/1440
                """,
                {"user_id": user_id, "trans_type": "이체"}
            )
            cnt = cursor.fetchone()[0]
            # 이번 이체가 곧 3번째 이상인 경우: 기존 건수가 2건 이상이면 기록
            if cnt >= 2:
                record_audit_log(
                    self.conn, user_id, None,
                    "이상 거래 감지: 1분 내 연속 이체 3회 이상 패턴"
                )
                self.conn.commit()
                print("  ⚠️  이상 거래 감지: 1분 내 다수 이체로 감사로그에 기록되었습니다.")
        except Exception as e:
            self.conn.rollback()
            print(f"  ⚠️  F-09 감사로그 기록 실패 → {str(e)}")
        finally:
            cursor.close()

    def _block_voice_phishing(self, user_id, acc_id, amount, reason, trans_type):
        """
        F-10: 보이스피싱 의심 즉시 차단 — 거래내역(차단) + AUDIT_LOG
        trans_type: '이체' 또는 '출금'
        """
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO TRANSACTION_HISTORY
                    (TRANS_ID, ACC_ID, STATUS_ID, TRANS_TYPE,
                     AMOUNT, AFTER_BALANCE, MEMO, TRANS_DATE)
                VALUES
                    (SEQ_TRANS_ID.NEXTVAL, :acc_id, :status_id, :trans_type,
                     :amount, NULL, :memo, SYSDATE)
                """,
                {
                    "acc_id": acc_id,
                    "status_id": 5,
                    "trans_type": trans_type,
                    "amount": amount,
                    "memo": f"[보이스피싱 의심-차단] {reason}",
                }
            )
            cursor.execute("SELECT SEQ_TRANS_ID.CURRVAL FROM DUAL")
            trans_id = cursor.fetchone()[0]
            record_audit_log(
                self.conn, user_id, trans_id,
                f"[보이스피싱 의심] {reason} / 유형:{trans_type} / 금액:{amount:,.0f}원"
            )
            self.conn.commit()
            print("  📋 차단 내역이 거래내역 및 감사로그(AUDIT_LOG)에 기록되었습니다.")
        except Exception as e:
            self.conn.rollback()
            print(f"  ⚠️  차단 기록 실패 → {str(e)}")
        finally:
            cursor.close()

    def _insert_transaction(self, cursor, acc_id, status_id,
                            trans_type, amount, after_balance, memo):
        """TRANSACTION_HISTORY 삽입 (SEQ, SYSDATE는 SQL 직접)."""
        cursor.execute(
            """
            INSERT INTO TRANSACTION_HISTORY
                (TRANS_ID, ACC_ID, STATUS_ID, TRANS_TYPE,
                 AMOUNT, AFTER_BALANCE, MEMO, TRANS_DATE)
            VALUES
                (SEQ_TRANS_ID.NEXTVAL, :acc_id, :status_id, :trans_type,
                 :amount, :after_balance, :memo, SYSDATE)
            """,
            {
                "acc_id": acc_id,
                "status_id": status_id,
                "trans_type": trans_type,
                "amount": amount,
                "after_balance": after_balance,
                "memo": memo,
            }
        )
        cursor.execute("SELECT SEQ_TRANS_ID.CURRVAL FROM DUAL")
        return cursor.fetchone()[0]

    def deposit(self, user_id):
        """회원 입금: MEMO는 사용자 입력(없으면 기본 '입금')."""
        from account import select_my_account

        print("\n[ 입금 ]")
        acc_id = select_my_account(self.conn, user_id)
        if acc_id is None:
            return

        try:
            amount = int(input("  입금할 금액을 입력하세요 (원): ").replace(",", ""))
            if amount <= 0:
                print("  ❌ 금액은 0보다 커야 합니다.")
                return
        except ValueError:
            print("  ❌ 올바른 숫자를 입력하세요.")
            return

        memo = input("  메모 (선택, Enter 생략): ").strip() or "입금"

        cursor = self.conn.cursor()
        try:
            cursor.execute(
                """
                SELECT BALANCE
                FROM   ACCOUNT
                WHERE  ACC_ID = :acc_id
                FOR UPDATE
                """,
                {"acc_id": acc_id}
            )
            row = cursor.fetchone()
            if row is None:
                print("  ❌ 계좌를 찾을 수 없습니다.")
                return

            current_balance = row[0]
            new_balance     = current_balance + amount

            cursor.execute(
                """
                UPDATE ACCOUNT
                SET    BALANCE = :new_balance
                WHERE  ACC_ID  = :acc_id
                """,
                {"new_balance": new_balance, "acc_id": acc_id}
            )

            self._insert_transaction(
                cursor, acc_id, 1, "입금", amount, new_balance, memo
            )

            self.conn.commit()
            print(f"  ✅ 입금 완료! 현재 잔액: {new_balance:,.0f} 원")

        except Exception as e:
            self.conn.rollback()
            print(f"  ❌ 입금 실패 → {str(e)}")
        finally:
            cursor.close()

    def withdraw(self, user_id):
        """출금: 상단 F-10(보이스피싱 의심) + 기존 이상패턴 검사."""
        from account import select_my_account

        print("\n[ 출금 ]")
        acc_id = select_my_account(self.conn, user_id)
        if acc_id is None:
            return

        try:
            amount = int(input("  출금할 금액을 입력하세요 (원): ").replace(",", ""))
            if amount <= 0:
                print("  ❌ 금액은 0보다 커야 합니다.")
                return
        except ValueError:
            print("  ❌ 올바른 숫자를 입력하세요.")
            return

        # ── 보이스피싱 탐지 (F-10 등) — 금액 확정 직후 ──
        status, msg = self.check_suspicious_activity(user_id, amount)
        if status == "BLOCK":
            print(f"\n  🚫 {msg}")
            print("  거래가 즉시 차단되었습니다. 의심되면 금융감독원(1332)에 신고하세요.")
            self._block_voice_phishing(user_id, acc_id, amount, msg, "출금")
            return

        memo = input("  메모 (선택, Enter 생략): ").strip() or "출금"

        cursor = self.conn.cursor()
        try:
            cursor.execute(
                """
                SELECT BALANCE
                FROM   ACCOUNT
                WHERE  ACC_ID = :acc_id
                FOR UPDATE
                """,
                {"acc_id": acc_id}
            )
            row = cursor.fetchone()
            if row is None:
                print("  ❌ 계좌를 찾을 수 없습니다.")
                return

            current_balance = row[0]
            if current_balance < amount:
                print(f"  ❌ 잔액 부족! 현재 잔액: {current_balance:,.0f} 원")
                return

            new_balance = current_balance - amount

            cursor.execute(
                """
                UPDATE ACCOUNT
                SET    BALANCE = :new_balance
                WHERE  ACC_ID  = :acc_id
                """,
                {"new_balance": new_balance, "acc_id": acc_id}
            )

            self._insert_transaction(
                cursor, acc_id, 1, "출금", amount, new_balance, memo
            )

            self.conn.commit()
            print(f"  ✅ 출금 완료! 현재 잔액: {new_balance:,.0f} 원")

        except Exception as e:
            self.conn.rollback()
            print(f"  ❌ 출금 실패 → {str(e)}")
        finally:
            cursor.close()

    def transfer_money(self, user_id):
        """
        이체: 상단 F-10 차단, F-09 감사로그, F-08(100만 이상 지연대기 + 1시간 후 처리 안내)
        """
        from account import select_my_account

        print("\n[ 계좌이체 ]")
        sender_acc_id = select_my_account(
            self.conn, user_id, "  출금 계좌 번호를 선택하세요: "
        )
        if sender_acc_id is None:
            return

        recv_acc_num = input("  수취 계좌번호를 입력하세요: ").strip()
        if not recv_acc_num or len(recv_acc_num) > _MAX_ACC_NUM_VARCHAR2:
            print(
                f"  ❌ 수취 계좌번호는 1~{_MAX_ACC_NUM_VARCHAR2}자 **문자열**이어야 합니다 "
                f"(DB VARCHAR2(30), int 변환 금지)."
            )
            return

        try:
            amount = int(input("  이체 금액을 입력하세요 (원): ").replace(",", ""))
            if amount <= 0:
                print("  ❌ 금액은 0보다 커야 합니다.")
                return
        except ValueError:
            print("  ❌ 올바른 숫자를 입력하세요.")
            return

        memo = input("  메모 (선택, Enter 생략): ").strip() or "이체"

        # ── F-10: 1,000만원 초과 — 보이스피싱 의심 즉시 차단 + AUDIT_LOG ──
        suspicion_status, suspicion_msg = self.check_suspicious_activity(user_id, amount)
        if suspicion_status == "BLOCK":
            print(f"\n  🚫 {suspicion_msg}")
            print("  거래가 즉시 차단되었습니다. 의심되면 금융감독원(1332)에 신고하세요.")
            self._block_voice_phishing(user_id, sender_acc_id, amount, suspicion_msg, "이체")
            return

        # ── F-09: 1분 내 연속 이체 3회 이상 패턴 → 감사로그만 ──
        self._f09_log_rapid_transfers(user_id)

        cursor = self.conn.cursor()
        try:
            cursor.execute(
                """
                SELECT BALANCE
                FROM   ACCOUNT
                WHERE  ACC_ID = :sender_acc_id
                FOR UPDATE
                """,
                {"sender_acc_id": sender_acc_id}
            )
            sender_row = cursor.fetchone()
            if sender_row is None:
                print("  ❌ 출금 계좌를 찾을 수 없습니다.")
                return

            sender_balance = sender_row[0]
            if sender_balance < amount:
                print(f"  ❌ 잔액 부족! 현재 잔액: {sender_balance:,.0f} 원")
                return

            cursor.execute(
                """
                SELECT ACC_ID, BALANCE
                FROM   ACCOUNT
                WHERE  ACC_NUM = :recv_acc_num
                FOR UPDATE
                """,
                {"recv_acc_num": recv_acc_num}
            )
            recv_row = cursor.fetchone()
            if recv_row is None:
                print(f"  ❌ 수취 계좌번호 [{recv_acc_num}]를 찾을 수 없습니다.")
                return

            recv_acc_id, recv_balance = recv_row

            # ── F-08: 100만원 이상 — 지연대기(STATUS 4), 1시간 후 처리 안내 ──
            if amount >= 1_000_000:
                # [참고] 지연 이체는 “인증 전” 1차 commit 과 “인증 실패 시 복구” 2차 트랜잭션으로
                # 비즈니스 규칙상 Unit of Work 가 둘로 나뉨(전자는 송금 반영+내역 확정, 후자는 롤백성 복구).
                print("\n  💡 [F-08 지연 이체] 100만원 이상 이체입니다.")
                print("      거래 상태가 「지연대기」로 설정되었으며, 2차 인증 후 **1시간 뒤** 수취 계좌에 입금됩니다.")

                # [F-08 1단계 UoW] 송금 잔액 차감 + 지연대기 거래내역 + 이체상세 → 한 번에 commit
                new_sender_balance = sender_balance - amount
                cursor.execute(
                    """
                    UPDATE ACCOUNT
                    SET    BALANCE = :sender_new_balance
                    WHERE  ACC_ID  = :sender_acc_id
                    """,
                    {
                        "sender_new_balance": new_sender_balance,
                        "sender_acc_id": sender_acc_id,
                    }
                )
                trans_id = self._insert_transaction(
                    cursor, sender_acc_id, 4, "이체",
                    amount, new_sender_balance,
                    f"[지연대기] {memo} → {recv_acc_num}"
                )
                cursor.execute(
                    """
                    INSERT INTO TRANSFER_DETAIL
                        (TRANSFER_ID, TRANS_ID, RECV_ACC_NUM, RECV_MEMO)
                    VALUES
                        (SEQ_DETAIL_ID.NEXTVAL, :trans_id, :recv_acc_num, :recv_memo)
                    """,
                    {
                        "trans_id": trans_id,
                        "recv_acc_num": recv_acc_num,
                        "recv_memo": f"[지연대기] {memo}",
                    }
                )
                self.conn.commit()

                auth_code, expire_at = request_second_auth(
                    self.conn, user_id, trans_id
                )
                if auth_code is None:
                    return

                input_code = input("  인증 코드 6자리를 입력하세요: ").strip()
                if not verify_second_auth(self.conn, trans_id, input_code):
                    cursor2 = self.conn.cursor()
                    try:
                        cursor2.execute(
                            """
                            UPDATE TRANSACTION_HISTORY
                            SET    STATUS_ID = :fail_status_id
                            WHERE  TRANS_ID  = :trans_id
                            """,
                            {"fail_status_id": 2, "trans_id": trans_id}
                        )
                        cursor2.execute(
                            """
                            UPDATE ACCOUNT
                            SET    BALANCE = :restore_balance
                            WHERE  ACC_ID  = :sender_acc_id
                            """,
                            {
                                "restore_balance": sender_balance,
                                "sender_acc_id": sender_acc_id,
                            }
                        )
                        self.conn.commit()
                    except Exception as e:
                        self.conn.rollback()
                        print(f"  ❌ 인증 실패 후 복구 오류 → {str(e)}")
                    finally:
                        cursor2.close()
                    print("  ❌ 2차 인증 실패로 이체가 취소되었습니다.")
                    return

                print("  ✅ 인증 성공! 이체 요청이 접수되었습니다.")
                print("     ※ [F-08] 수취 계좌 반영은 **1시간 후** 처리됩니다. (지연대기)")
                print(f"     출금 후 잔액: {new_sender_balance:,.0f} 원")

            else:
                # ─────────────────────────────────────────────────────────
                # [일반 이체 — 단일 Unit of Work / 원자성(Atomicity)]
                # 한 작업으로 묶이는 DB 변경:
                #   ① 출금 계좌 잔액 UPDATE  ② 입금 계좌 잔액 UPDATE
                #   ③ 송금 측 TRANSACTION_HISTORY INSERT
                #   ④ TRANSFER_DETAIL INSERT
                #   ⑤ 수취 측 TRANSACTION_HISTORY INSERT
                # 위 모두 같은 autocommit=False 세션에서 실행되며, **commit 은 맨 아래 한 번**만 수행.
                # 그 전에 예외가 나면 except 에서 conn.rollback() 으로 ①~⑤ 전부 되돌림(전부 성공 또는 전부 무효).
                # ─────────────────────────────────────────────────────────
                new_sender_balance = sender_balance - amount
                new_recv_balance   = recv_balance + amount

                cursor.execute(
                    """
                    UPDATE ACCOUNT
                    SET    BALANCE = :sender_new_balance
                    WHERE  ACC_ID  = :sender_acc_id
                    """,
                    {
                        "sender_new_balance": new_sender_balance,
                        "sender_acc_id": sender_acc_id,
                    }
                )
                cursor.execute(
                    """
                    UPDATE ACCOUNT
                    SET    BALANCE = :recv_new_balance
                    WHERE  ACC_ID  = :recv_acc_id
                    """,
                    {
                        "recv_new_balance": new_recv_balance,
                        "recv_acc_id": recv_acc_id,
                    }
                )

                trans_id = self._insert_transaction(
                    cursor, sender_acc_id, 1, "이체",
                    amount, new_sender_balance,
                    f"{memo} → {recv_acc_num}"
                )
                cursor.execute(
                    """
                    INSERT INTO TRANSFER_DETAIL
                        (TRANSFER_ID, TRANS_ID, RECV_ACC_NUM, RECV_MEMO)
                    VALUES
                        (SEQ_DETAIL_ID.NEXTVAL, :trans_id, :recv_acc_num, :recv_memo)
                    """,
                    {
                        "trans_id": trans_id,
                        "recv_acc_num": recv_acc_num,
                        "recv_memo": memo,
                    }
                )
                self._insert_transaction(
                    cursor, recv_acc_id, 1, "입금",
                    amount, new_recv_balance,
                    f"{memo} ← 이체 수신"
                )

                self.conn.commit()
                print("  ✅ 이체 완료!")
                print(f"     송금 후 잔액: {new_sender_balance:,.0f} 원")

        except Exception as e:
            self.conn.rollback()
            print(f"  ❌ 이체 실패 → {str(e)}")
        finally:
            cursor.close()

    def show_history(self, user_id):
        """거래 내역 조회"""
        from account import select_my_account

        print("\n[ 거래 내역 조회 ]")
        acc_id = select_my_account(self.conn, user_id)
        if acc_id is None:
            return

        cursor = self.conn.cursor()
        try:
            cursor.execute(
                """
                SELECT TH.TRANS_DATE, TH.TRANS_TYPE, TH.AMOUNT,
                       TH.AFTER_BALANCE, TS.STATUS_NAME, TH.MEMO
                FROM   TRANSACTION_HISTORY TH
                JOIN   TRANSACTION_STATUS  TS ON TH.STATUS_ID = TS.STATUS_ID
                WHERE  TH.ACC_ID = :acc_id
                ORDER BY TH.TRANS_DATE DESC
                FETCH FIRST 20 ROWS ONLY
                """,
                {"acc_id": acc_id}
            )
            rows = cursor.fetchall()

            if not rows:
                print("  거래 내역이 없습니다.")
                return

            print(f"\n  {'날짜':<22} {'유형':<6} {'금액':>14} {'잔액':>14} {'상태':<8} 메모")
            print("  " + "-" * 80)
            for r in rows:
                trans_date, trans_type, amount, after_bal, status_name, memo = r
                date_str = trans_date.strftime("%Y-%m-%d %H:%M:%S") if trans_date else "-"
                after_str = f"{after_bal:,.0f}" if after_bal is not None else "-"
                print(f"  {date_str:<22} {trans_type:<6} {amount:>14,.0f} "
                      f"{after_str:>14} {status_name:<8} {memo or ''}")
        except Exception as e:
            print(f"  ❌ 거래 내역 조회 실패 → {str(e)}")
        finally:
            cursor.close()


# ══════════════════════════════════════════════════════════════════════════
# 관리자용 거래/감사 조회 및 차단 (기존 TransactionManager와 분리된 함수명)
# ══════════════════════════════════════════════════════════════════════════


def record_admin_audit_log(conn, admin_user_id, transaction_id, action, detail):
    """
    관리자 작업을 AUDIT_LOG에 기록합니다.
    - 요구사항 문서의 'AUDIT_LOGS'가 아니라 실제 스키마 테이블명은 AUDIT_LOG 입니다.
    - transaction_id 없을 수 있음 → NULL 바인드
    - ACTION 컬럼(VARCHAR2 100)에 action|detail 요약 저장
    """
    parts = []
    if action is not None:
        parts.append(str(action))
    if detail is not None:
        parts.append(str(detail))
    full_action = "|".join(parts)[:100]

    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO AUDIT_LOG
                (LOG_ID, USER_ID, TRANS_ID, ACTION, IP_ADDR, LOG_DATE)
            VALUES
                (SEQ_LOG_ID.NEXTVAL, :log_user_id, :log_trans_id, :log_action, :log_ip, SYSDATE)
            """,
            {
                "log_user_id": admin_user_id,
                "log_trans_id": transaction_id,
                "log_action": full_action,
                "log_ip": _get_ip(),
            }
        )
    finally:
        cursor.close()


def admin_list_all_transactions(conn):
    """전체 거래내역: 거래ID, 고객명, 계좌번호, 유형, 금액, 상태명, 일시"""
    print("\n=== [ 전체 거래내역 조회 ] ===")
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT TH.TRANS_ID,
                   U.NAME,
                   AC.ACC_NUM,
                   TH.TRANS_TYPE,
                   TH.AMOUNT,
                   TS.STATUS_NAME,
                   TH.TRANS_DATE
            FROM   TRANSACTION_HISTORY TH
            JOIN   ACCOUNT              AC ON TH.ACC_ID = AC.ACC_ID
            JOIN   USERS                U ON AC.USER_ID = U.USER_ID
            JOIN   TRANSACTION_STATUS  TS ON TH.STATUS_ID = TS.STATUS_ID
            ORDER BY TH.TRANS_DATE DESC
            FETCH FIRST 150 ROWS ONLY
            """
        )
        rows = cursor.fetchall()
        if not rows:
            print("  거래 내역이 없습니다.")
            return
        print(f"\n  {'TID':<8} {'고객명':<10} {'계좌번호':<22} {'유형':<6} {'금액':>14} {'상태':<10} {'거래일시'}")
        print("  " + "-" * 92)
        for r in rows:
            tid, nm, accn, ttype, amt, stname, tdt = r
            ds = tdt.strftime("%Y-%m-%d %H:%M:%S") if tdt else "-"
            print(f"  {tid:<8} {str(nm or '')[:10]:<10} {str(accn or '')[:22]:<22} {str(ttype or '')[:6]:<6} "
                  f"{amt:>14,.0f} {str(stname or '')[:10]:<10} {ds}")
    except Exception as e:
        print(f"  ❌ 조회 실패 → {str(e)}")
    finally:
        cursor.close()


def admin_search_transactions(conn):
    """최소 금액 이상 거래만 조회 (단순 기준)."""
    print("\n=== [ 거래 검색 (금액 기준) ] ===")
    raw = input("  조회할 최소 금액(원, 숫자만): ").strip().replace(",", "")
    if not raw.isdigit():
        print("  ❌ 숫자만 입력하세요.")
        return
    min_amt = int(raw)
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT TH.TRANS_ID,
                   U.NAME,
                   AC.ACC_NUM,
                   TH.TRANS_TYPE,
                   TH.AMOUNT,
                   TS.STATUS_NAME,
                   TH.TRANS_DATE
            FROM   TRANSACTION_HISTORY TH
            JOIN   ACCOUNT              AC ON TH.ACC_ID = AC.ACC_ID
            JOIN   USERS                U ON AC.USER_ID = U.USER_ID
            JOIN   TRANSACTION_STATUS  TS ON TH.STATUS_ID = TS.STATUS_ID
            WHERE  TH.AMOUNT >= :min_amt
            ORDER BY TH.TRANS_DATE DESC
            FETCH FIRST 100 ROWS ONLY
            """,
            {"min_amt": min_amt}
        )
        rows = cursor.fetchall()
        if not rows:
            print("  조건에 맞는 거래가 없습니다.")
            return
        print(f"\n  {'TID':<8} {'고객명':<10} {'계좌번호':<22} {'유형':<6} {'금액':>14} {'상태':<10} {'거래일시'}")
        print("  " + "-" * 92)
        for r in rows:
            tid, nm, accn, ttype, amt, stname, tdt = r
            ds = tdt.strftime("%Y-%m-%d %H:%M:%S") if tdt else "-"
            print(f"  {tid:<8} {str(nm or '')[:10]:<10} {str(accn or '')[:22]:<22} {str(ttype or '')[:6]:<6} "
                  f"{amt:>14,.0f} {str(stname or '')[:10]:<10} {ds}")
    except Exception as e:
        print(f"  ❌ 검색 실패 → {str(e)}")
    finally:
        cursor.close()


def admin_list_suspicious_transactions(conn):
    """
    의심 거래 조회.
    - (a) 금액 100만원 이상
    - (b) 상태: 인증대기 / 지연대기 / 차단
    - (c) 감사로그(AUDIT_LOG)에 TRANS_ID가 연결된 거래
    """
    print("\n=== [ 의심 거래 조회 ] ===")
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT DISTINCT
                   TH.TRANS_ID,
                   U.NAME,
                   AC.ACC_NUM,
                   TH.TRANS_TYPE,
                   TH.AMOUNT,
                   TS.STATUS_NAME,
                   TH.TRANS_DATE,
                   TH.MEMO
            FROM   TRANSACTION_HISTORY TH
            JOIN   ACCOUNT              AC ON TH.ACC_ID = AC.ACC_ID
            JOIN   USERS                U ON AC.USER_ID = U.USER_ID
            JOIN   TRANSACTION_STATUS  TS ON TH.STATUS_ID = TS.STATUS_ID
            WHERE  TH.AMOUNT >= :min_amt
               OR  TS.STATUS_NAME IN (:st_wait_auth, :st_delay, :st_block)
               OR  EXISTS (
                       SELECT 1
                       FROM   AUDIT_LOG AL
                       WHERE  AL.TRANS_ID = TH.TRANS_ID
                   )
            ORDER BY TH.TRANS_DATE DESC
            FETCH FIRST 150 ROWS ONLY
            """,
            {
                "min_amt": 1_000_000,
                "st_wait_auth": "인증대기",
                "st_delay": "지연대기",
                "st_block": "차단",
            }
        )
        rows = cursor.fetchall()
        if not rows:
            print("  의심 조건에 해당하는 거래가 없습니다.")
            return
        print(f"\n  {'TID':<8} {'고객명':<8} {'계좌번호':<20} {'유형':<6} {'금액':>12} {'상태':<10} {'일시':<20} 메모")
        print("  " + "-" * 100)
        for r in rows:
            tid, nm, accn, ttype, amt, stname, tdt, memo = r
            ds = tdt.strftime("%Y-%m-%d %H:%M") if tdt else "-"
            print(f"  {tid:<8} {str(nm or '')[:8]:<8} {str(accn or '')[:20]:<20} {str(ttype or '')[:6]:<6} "
                  f"{amt:>12,.0f} {str(stname or '')[:10]:<10} {ds:<20} {str(memo or '')[:30]}")
    except Exception as e:
        print(f"  ❌ 조회 실패 → {str(e)}")
    finally:
        cursor.close()


def admin_block_transaction(conn, admin_user):
    """
    거래 강제 차단: TRANS_ID 입력 → TRANSACTION_STATUS에서 '차단' 또는 'BLOCKED' ID 조회 후 반영.
    성공 시 record_admin_audit_log 로 관리자 조치 기록.
    """
    print("\n=== [ 거래 강제 차단 ] ===")
    raw = input("  차단 처리할 TRANS_ID: ").strip()
    if not raw.isdigit():
        print("  ❌ 숫자 TRANS_ID를 입력하세요.")
        return
    trans_id = int(raw)

    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT STATUS_ID
            FROM   TRANSACTION_STATUS
            WHERE  UPPER(TRIM(STATUS_NAME)) = UPPER(TRIM(:name1))
               OR  UPPER(TRIM(STATUS_NAME)) = UPPER(TRIM(:name2))
            FETCH FIRST 1 ROW ONLY
            """,
            {"name1": "차단", "name2": "BLOCKED"}
        )
        st = cursor.fetchone()
        if st is None:
            print("  ❌ TRANSACTION_STATUS에 '차단' 또는 'BLOCKED' 행이 없습니다. DB_Setup.sql을 확인하세요.")
            return
        block_status_id = st[0]

        cursor.execute(
            """
            SELECT TRANS_ID
            FROM   TRANSACTION_HISTORY
            WHERE  TRANS_ID = :trans_id
            """,
            {"trans_id": trans_id}
        )
        if cursor.fetchone() is None:
            print("  ❌ 해당 TRANS_ID 거래가 없습니다.")
            return

        cursor.execute(
            """
            UPDATE TRANSACTION_HISTORY
            SET    STATUS_ID = :block_status_id
            WHERE  TRANS_ID  = :trans_id
            """,
            {"block_status_id": block_status_id, "trans_id": trans_id}
        )

        record_admin_audit_log(
            conn,
            admin_user["user_id"],
            trans_id,
            "ADMIN_FORCE_BLOCK",
            f"관리자가 거래 상태를 차단으로 변경 (TRANS_ID={trans_id})",
        )
        conn.commit()
        print(f"  ✅ TRANS_ID {trans_id} 거래를 차단 상태(STATUS_ID={block_status_id})로 변경했습니다.")
    except Exception as e:
        conn.rollback()
        print(f"  ❌ 차단 처리 실패 → {str(e)}")
    finally:
        cursor.close()


def admin_list_audit_logs(conn):
    """감사로그(AUDIT_LOG) 최근 내역 조회"""
    print("\n=== [ 감사로그 조회 ] ===")
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT LOG_ID, USER_ID, TRANS_ID, ACTION, IP_ADDR, LOG_DATE
            FROM   AUDIT_LOG
            ORDER BY LOG_DATE DESC
            FETCH FIRST 120 ROWS ONLY
            """
        )
        rows = cursor.fetchall()
        if not rows:
            print("  감사로그가 없습니다.")
            return
        print(f"\n  {'LOG':<8} {'USER_ID':<10} {'TRANS_ID':<10} {'ACTION':<40} {'IP':<16} {'일시'}")
        print("  " + "-" * 100)
        for r in rows:
            lid, uid, tid, act, ip, ldt = r
            ds = ldt.strftime("%Y-%m-%d %H:%M:%S") if ldt else "-"
            print(f"  {lid:<8} {str(uid) if uid is not None else 'NULL':<10} "
                  f"{str(tid) if tid is not None else 'NULL':<10} "
                  f"{str(act or '')[:40]:<40} {str(ip or '')[:16]:<16} {ds}")
    except Exception as e:
        print(f"  ❌ 조회 실패 → {str(e)}")
    finally:
        cursor.close()

# ──────────────────────────────────────────────
# account.py  –  계좌 관리 모듈
# ──────────────────────────────────────────────
#
# [DB(1. DB_Setup.sql) vs 본 모듈 / 회원 도메인]
# - 본 프로젝트에는 member.py 가 없습니다. 회원(USERS) 생성·로그인은 auth.py 가 담당합니다.
# - account.py 는 ACCOUNT / BANK 와 직접 매핑되는 “계좌” 도메인만 다룹니다.
#
# [제약 조건 vs 코드 검증 — 요약]
# - ACCOUNT.ACC_NUM: VARCHAR2(30) UNIQUE NOT NULL → 계좌번호는 항상 str 로 취급(int 변환 금지).
# - ACCOUNT.ALIAS: VARCHAR2(30) (NULL 허용) → 길이 30자 초과 시 앱에서 거절.
# - USERS.NAME 등은 auth.py 에서 VARCHAR2(30) NOT NULL 과 맞게 검증.
# - 스키마에 phone 컬럼 없음 → 전화번호 검증·저장 로직 없음(ERD에만 있다면 별도 마이그레이션 필요).
#
# [3NF / 반정규화 — ACCOUNT.BALANCE]
# - 순수 3NF라면 잔액은 TRANSACTION_HISTORY 만으로 재계산 가능합니다.
# - 그러나 매 조회마다 합산하면 비용이 크므로, ACCOUNT.BALANCE 는 “거래 합계의 캐시(반정규화)”로 둡니다.
# - 이행적 함수 종속: “계좌 → 최신 잔액”이 이론상 거래 집계에 종속되지만, 성능·동시성(행 잠금)을 위해
#   같은 트랜잭션 안에서 거래 기록과 함께 잔액을 갱신하는 방식으로 정합성을 맞춥니다.
#   (교수님 설명용: 의도적 반정규화 + 트랜잭션으로 불일치 방지)
#
# 바인드 변수: SQL :이름 = dict 키 (ORA-01745 방지). SYSDATE / SEQ 는 SQL 직접 기술.

import random

# DB VARCHAR2 길이 상수 (1. DB_Setup.sql 과 동일)
_MAX_ACC_NUM_LEN = 30
_MAX_ALIAS_LEN = 30


def _validate_varchar2(value, max_len, field_label, allow_empty=False):
    """
    Oracle VARCHAR2(max_len) 제약에 맞게 문자열만 허용하고 길이를 검사합니다.
    계좌번호(account_number)·전화번호 등은 int 가 아닌 str 로만 다룹니다.
    """
    if value is None:
        return False, f"{field_label}: 값이 없습니다."
    s = str(value).strip()
    if not s and not allow_empty:
        return False, f"{field_label}: 빈 문자열은 허용되지 않습니다."
    if len(s) > max_len:
        return False, f"{field_label}: 최대 {max_len}자까지입니다(DB VARCHAR2 제약)."
    return True, s

def show_bank_list(conn):
    """
    BANK 테이블에서 은행 목록을 조회하고 사용자 선택을 받습니다.
    - 번호(순서 인덱스) 또는 은행 이름(예: '하나')으로 선택 가능
    - 선택된 은행의 실제 BANK_ID를 DB에서 직접 조회하여 반환
    반환값: (bank_id, bank_name) 또는 실패 시 (None, None)
    """
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT BANK_ID, BANK_NAME, BANK_CODE FROM BANK ORDER BY BANK_ID")
        banks = cursor.fetchall()

        if not banks:
            print("  ❌ BANK 테이블에 등록된 은행이 없습니다. DB_Setup.sql을 먼저 실행하세요.")
            return None, None

        print("\n  [ 은행 목록 ]  번호 또는 이름으로 선택하세요")
        for idx, b in enumerate(banks, start=1):
            print(f"    {idx}. {b[1]} ({b[2]})")

        raw = input("  번호 또는 은행 이름 입력 (예: 1  또는  하나): ").strip()

        if raw.isdigit():
            idx = int(raw)
            if 1 <= idx <= len(banks):
                chosen = banks[idx - 1]
                cursor.execute(
                    "SELECT BANK_ID, BANK_NAME FROM BANK WHERE BANK_ID = :bank_id",
                    {"bank_id": chosen[0]}
                )
                row = cursor.fetchone()
                if row:
                    return row[0], row[1]
        else:
            cursor.execute(
                "SELECT BANK_ID, BANK_NAME FROM BANK WHERE BANK_NAME = :bank_name",
                {"bank_name": raw}
            )
            row = cursor.fetchone()
            if row:
                return row[0], row[1]

        print(f"  ❌ '{raw}'에 해당하는 은행을 찾을 수 없습니다.")
        return None, None
    except Exception as e:
        print(f"  ❌ 은행 목록 조회 실패: {str(e)}")
        return None, None
    finally:
        cursor.close()


def register_account(conn, user_id):
    """
    계좌 등록 (F-03, F-04)
    - 세션 user_id가 USERS에 존재하는지 검증
    - 은행별 1계좌 제한
    """
    print("\n[ 계좌 등록 ]")

    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM   USERS
            WHERE  USER_ID     = :user_id
              AND  IS_DELETED = :is_deleted
            """,
            {"user_id": user_id, "is_deleted": "N"}
        )
        cnt = cursor.fetchone()[0]
        if cnt == 0:
            print(f"  ❌ 세션 오류: USER_ID={user_id} 에 해당하는 유효한 회원을 찾을 수 없습니다.")
            return
    except Exception as e:
        print(f"  ❌ 사용자 확인 중 오류: {str(e)}")
        return
    finally:
        cursor.close()

    bank_id, bank_name = show_bank_list(conn)
    if bank_id is None:
        return

    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM   ACCOUNT
            WHERE  USER_ID = :user_id
              AND  BANK_ID = :bank_id
            """,
            {"user_id": user_id, "bank_id": bank_id}
        )
        count = cursor.fetchone()[0]
        if count > 0:
            print(f"  ❌ {bank_name} 은행(BANK_ID={bank_id})에는 이미 계좌가 등록되어 있습니다. (은행별 1개 제한)")
            return

        # 은행 코드 조회 (계좌번호 앞자리)
        cursor.execute(
            "SELECT BANK_CODE FROM BANK WHERE BANK_ID = :bank_id",
            {"bank_id": bank_id}
        )
        code_row = cursor.fetchone()
        if code_row is None or not str(code_row[0]).strip():
            print("  ❌ 은행 코드(BANK_CODE)를 찾을 수 없습니다.")
            return
        bank_code = str(code_row[0]).strip()

        # '은행코드-00-랜덤8자리' 형식으로 고유 계좌번호 자동 생성
        acc_num = None
        for _ in range(50):
            suffix = f"{random.randint(0, 99999999):08d}"
            candidate = f"{bank_code}-00-{suffix}"
            cursor.execute(
                "SELECT COUNT(*) FROM ACCOUNT WHERE ACC_NUM = :acc_num",
                {"acc_num": candidate}
            )
            if cursor.fetchone()[0] == 0:
                acc_num = candidate
                break

        if acc_num is None:
            print("  ❌ 사용 가능한 계좌번호를 만들지 못했습니다. 잠시 후 다시 시도해 주세요.")
            return

        # ACC_NUM 은 DB에서 VARCHAR2 → Python str 유지 (정수형으로 파싱하지 않음)
        ok_len, msg = _validate_varchar2(acc_num, _MAX_ACC_NUM_LEN, "계좌번호(ACC_NUM)")
        if not ok_len:
            print(f"  ❌ {msg}")
            return

        alias = input("  계좌 별칭을 입력하세요 (예: 내 월급통장): ").strip()
        ok_al, alias_norm = _validate_varchar2(alias, _MAX_ALIAS_LEN, "별칭(ALIAS)", allow_empty=True)
        if not ok_al:
            print(f"  ❌ {alias_norm}")
            return
        alias = alias_norm

        cursor.execute(
            """
            INSERT INTO ACCOUNT (ACC_ID, USER_ID, BANK_ID, ACC_NUM, BALANCE, ALIAS)
            VALUES (SEQ_ACC_ID.NEXTVAL, :user_id, :bank_id, :acc_num, 0, :alias)
            """,
            {"user_id": user_id, "bank_id": bank_id,
             "acc_num": acc_num, "alias": alias}
        )
        conn.commit()
        print(f"\n  생성된 계좌번호는 [{acc_num}] 입니다.")
        print(f"  ✅ [{bank_name}] 계좌가 등록되었습니다!")

    except Exception as e:
        conn.rollback()
        print(f"  ❌ 계좌 등록 실패 → {str(e)}")
    finally:
        cursor.close()


def get_my_accounts(conn, user_id):
    """
    현재 로그인 사용자의 계좌 목록 (ACCOUNT.USER_ID = 세션 user_id)
    """
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT A.ACC_ID, B.BANK_NAME, A.ACC_NUM, A.ALIAS, A.BALANCE
            FROM   ACCOUNT A
            JOIN   BANK    B ON A.BANK_ID = B.BANK_ID
            WHERE  A.USER_ID = :user_id
            ORDER BY A.ACC_ID
            """,
            {"user_id": user_id}
        )
        return cursor.fetchall()
    except Exception as e:
        print(f"  ❌ 계좌 목록 조회 실패 → {str(e)}")
        return []
    finally:
        cursor.close()


def check_balance(conn, user_id):
    """잔액 조회 (F-05)"""
    print("\n[ 잔액 조회 ]")
    accounts = get_my_accounts(conn, user_id)

    if not accounts:
        print("  등록된 계좌가 없습니다.")
        return

    print(f"\n  {'번호':<4} {'은행':<8} {'계좌번호':<20} {'별칭':<15} {'잔액':>15}")
    print("  " + "-" * 65)
    for idx, acc in enumerate(accounts, start=1):
        acc_id, bank_name, acc_num, alias, balance = acc
        print(f"  {idx:<4} {bank_name:<8} {acc_num:<20} {alias or '':<15} {balance:>15,.0f} 원")


def select_my_account(conn, user_id, prompt="  사용할 계좌 번호를 선택하세요: "):
    """거래 시 계좌 선택. 반환: acc_id 또는 None"""
    accounts = get_my_accounts(conn, user_id)

    if not accounts:
        print("  ❌ 등록된 계좌가 없습니다. 먼저 계좌를 등록해주세요.")
        return None

    print(f"\n  {'번호':<4} {'은행':<8} {'계좌번호':<20} {'별칭':<15} {'잔액':>15}")
    print("  " + "-" * 65)
    for idx, acc in enumerate(accounts, start=1):
        acc_id, bank_name, acc_num, alias, balance = acc
        print(f"  {idx:<4} {bank_name:<8} {acc_num:<20} {alias or '':<15} {balance:>15,.0f} 원")

    choice = input(prompt).strip()
    if choice.isdigit() and 1 <= int(choice) <= len(accounts):
        return accounts[int(choice) - 1][0]

    print("  ❌ 잘못된 선택입니다.")
    return None


# ──────────────────────────────────────────────
# [관리자] 계좌 조회
# ──────────────────────────────────────────────
# admin_update_account_status 관련:
# 현재 DB_Setup.sql의 ACCOUNT 테이블에는 '정상/정지/제한' 등 계좌 상태(STATUS) 컬럼이 없습니다.
# ERD에만 존재한다면 컬럼 추가 후 UPDATE 로 구현하면 됩니다. (여기서는 함수를 두지 않음)


def admin_list_all_accounts(conn):
    """
    전체 계좌 조회 (관리자).
    - USERS, ACCOUNT, BANK 조인
    - 계좌 상태 컬럼이 없으므로 회원 삭제 여부로 '회원상태' 표시
    """
    print("\n=== [ 전체 계좌 조회 ] ===")
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT U.USER_ID,
                   U.NAME,
                   U.IS_DELETED,
                   B.BANK_NAME,
                   A.ACC_NUM,
                   A.ALIAS,
                   A.BALANCE,
                   A.ACC_ID
            FROM   ACCOUNT A
            JOIN   USERS U ON A.USER_ID = U.USER_ID
            JOIN   BANK  B ON A.BANK_ID = B.BANK_ID
            ORDER BY A.ACC_ID
            """
        )
        rows = cursor.fetchall()
        if not rows:
            print("  등록된 계좌가 없습니다.")
            return
        print(f"\n  {'ACC':<6} {'USER':<6} {'고객명':<10} {'회원상태':<10} {'은행':<8} {'계좌번호':<22} {'별칭':<12} {'잔액':>14}")
        print("  " + "-" * 95)
        for r in rows:
            uid, uname, is_del, bname, acc_num, alias, bal, acc_id = r
            mem_st = "탈퇴(Y)" if str(is_del).strip().upper() == "Y" else "정상"
            print(f"  {acc_id:<6} {uid:<6} {str(uname or '')[:10]:<10} {mem_st:<10} {str(bname or '')[:8]:<8} "
                  f"{str(acc_num or ''):<22} {str(alias or '')[:12]:<12} {bal:>14,.0f}")
        print("\n  ※ ACCOUNT 테이블에 별도 계좌 상태 컬럼은 없어, 회원 탈퇴 여부만 표시합니다.")

    except Exception as e:
        print(f"  ❌ 조회 실패 → {str(e)}")
    finally:
        cursor.close()


def admin_search_accounts_by_user(conn):
    """
    특정 회원의 계좌만 조회.
    - 입력이 숫자면 USER_ID, 아니면 고객 이름(NAME) LIKE 검색
    """
    print("\n=== [ 회원별 계좌 검색 ] ===")
    raw = input("  USER_ID(숫자) 또는 고객 이름: ").strip()
    if not raw:
        print("  ❌ 입력값이 없습니다.")
        return
    cursor = conn.cursor()
    try:
        if raw.isdigit():
            cursor.execute(
                """
                SELECT U.USER_ID, U.NAME, U.IS_DELETED,
                       B.BANK_NAME, A.ACC_NUM, A.ALIAS, A.BALANCE, A.ACC_ID
                FROM   ACCOUNT A
                JOIN   USERS U ON A.USER_ID = U.USER_ID
                JOIN   BANK  B ON A.BANK_ID = B.BANK_ID
                WHERE  U.USER_ID = :q_uid
                ORDER BY A.ACC_ID
                """,
                {"q_uid": int(raw)}
            )
        else:
            cursor.execute(
                """
                SELECT U.USER_ID, U.NAME, U.IS_DELETED,
                       B.BANK_NAME, A.ACC_NUM, A.ALIAS, A.BALANCE, A.ACC_ID
                FROM   ACCOUNT A
                JOIN   USERS U ON A.USER_ID = U.USER_ID
                JOIN   BANK  B ON A.BANK_ID = B.BANK_ID
                WHERE  U.NAME LIKE :q_name
                ORDER BY U.USER_ID, A.ACC_ID
                """,
                {"q_name": f"%{raw}%"}
            )
        rows = cursor.fetchall()
        if not rows:
            print("  조건에 맞는 계좌가 없습니다.")
            return
        print(f"\n  {'ACC':<6} {'USER':<6} {'고객명':<10} {'회원상태':<10} {'은행':<8} {'계좌번호':<22} {'별칭':<12} {'잔액':>14}")
        print("  " + "-" * 95)
        for r in rows:
            uid, uname, is_del, bname, acc_num, alias, bal, acc_id = r
            mem_st = "탈퇴(Y)" if str(is_del).strip().upper() == "Y" else "정상"
            print(f"  {acc_id:<6} {uid:<6} {str(uname or '')[:10]:<10} {mem_st:<10} {str(bname or '')[:8]:<8} "
                  f"{str(acc_num or ''):<22} {str(alias or '')[:12]:<12} {bal:>14,.0f}")
    except Exception as e:
        print(f"  ❌ 검색 실패 → {str(e)}")
    finally:
        cursor.close()


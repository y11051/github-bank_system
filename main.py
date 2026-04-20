"""
안전한 AI 은행 시스템 - 메인 실행 파일
========================================
- 비밀번호 입력은 auth 모듈에서 마스킹 처리됩니다(Windows: msvcrt, 그 외: getpass).

실행 전 필수 설치:
    pip install cx_Oracle

Oracle Instant Client 경로도 시스템에 맞게 설정하세요.
아래 cx_Oracle.init_oracle_client() 주석 참고.
"""

import oracledb
import sys

# ── 모듈 임포트 ────────────────────────────────────────────────────────────
from auth import (
    register,
    login,
    seed_admin,
    admin_list_users,
    admin_search_user,
    admin_soft_delete_user,
    admin_restore_user,
)
from account import (
    register_account,
    check_balance,
    admin_list_all_accounts,
    admin_search_accounts_by_user,
)
from transaction import (
    TransactionManager,
    guest_deposit,
    admin_list_all_transactions,
    admin_search_transactions,
    admin_list_suspicious_transactions,
    admin_block_transaction,
    admin_list_audit_logs,
)

# ──────────────────────────────────────────────────────────────────────────
# DB 연결 설정
# ──────────────────────────────────────────────────────────────────────────
# Oracle Instant Client가 PATH에 없으면 아래 줄 주석 해제 후 경로 수정
# cx_Oracle.init_oracle_client(lib_dir=r"C:\oracle\instantclient_21_x")

DB_USER     = "c##bank"      # ← 실제 사용자 계정으로 변경하세요
DB_PASSWORD = "123456"       # ← 실제 비밀번호로 변경하세요
DB_DSN      = "localhost:1521/free"   # ← 서버 주소/SID(서비스명) 확인 후 수정


def get_connection():
    """Oracle DB에 접속하고 connection 객체를 반환합니다."""
    try:
        conn = oracledb.connect(user=DB_USER, password=DB_PASSWORD, dsn=DB_DSN)
        return conn
    except oracledb.DatabaseError as e:
        print(f"\n❌ DB 접속 실패: {e}")
        print("   - system/oracle 계정과 localhost:1521/xe 연결 정보를 확인하세요.")
        print("   - Oracle Instant Client가 설치되어 있는지 확인하세요.")
        return None


# ──────────────────────────────────────────────────────────────────────────
# 로그인 후 메뉴 (회원 전용)
# ──────────────────────────────────────────────────────────────────────────

def user_menu(conn, user):
    """
    로그인된 사용자의 서비스 메뉴.
    while 루프로 '로그아웃' 선택 전까지 반복합니다.
    """
    tm = TransactionManager(conn)   # 거래 관리자 인스턴스 생성

    while True:
        print(f"\n=== [ {user['name']} 님 ] 서비스 메뉴 ===")
        print("  1. 계좌 등록")
        print("  2. 잔액 조회")
        print("  3. 입금")
        print("  4. 출금")
        print("  5. 계좌 이체")
        print("  6. 거래 내역 조회")
        print("  0. 로그아웃")
        print("-" * 38)

        choice = input("  메뉴를 선택하세요: ").strip()

        if choice == "1":
            register_account(conn, user["user_id"])

        elif choice == "2":
            check_balance(conn, user["user_id"])

        elif choice == "3":
            tm.deposit(user["user_id"])

        elif choice == "4":
            tm.withdraw(user["user_id"])

        elif choice == "5":
            tm.transfer_money(user["user_id"])

        elif choice == "6":
            tm.show_history(user["user_id"])

        elif choice == "0":
            print(f"\n  👋 '{user['name']}' 님, 안전하게 로그아웃되었습니다.")
            break

        else:
            print("  ❌ 잘못된 입력입니다. 다시 선택해주세요.")


# ──────────────────────────────────────────────────────────────────────────
# 메인 메뉴 (비로그인)
# ──────────────────────────────────────────────────────────────────────────

def main_menu(conn):
    """
    프로그램 시작 시 표시되는 메인 메뉴.
    while 루프로 '종료' 선택 전까지 반복합니다.
    """
    while True:
        print("\n" + "=" * 40)
        print("   🏦  안전한 AI 은행 시스템")
        print("=" * 40)
        print("  1. 회원가입")
        print("  2. 로그인")
        print("  3. 비회원 입금  (계좌번호·입금자명·금액만, 비밀번호 없음)")
        print("  0. 종료")
        print("-" * 40)

        choice = input("  메뉴를 선택하세요: ").strip()

        if choice == "1":
            register(conn)

        elif choice == "2":
            user = login(conn)
            if user:
                # ROLE에 따라 일반 회원 메뉴 vs 관리자 메뉴 분기
                role = (user.get("role") or "USER").strip().upper()
                if role == "ADMIN":
                    admin_menu(conn, user)
                else:
                    user_menu(conn, user)

        elif choice == "3":
            guest_deposit(conn)

        elif choice == "0":
            print("\n  시스템을 종료합니다. 감사합니다!")
            break

        else:
            print("  ❌ 잘못된 입력입니다. 다시 선택해주세요.")


# ──────────────────────────────────────────────────────────────────────────
# 관리자 메뉴 — 회원 USER_ID 사전 검증 (DB 존재 여부)
# ──────────────────────────────────────────────────────────────────────────

def _admin_user_id_exists(conn, user_id):
    """USERS 테이블에 해당 USER_ID 행이 있는지 확인합니다."""
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT USER_ID FROM USERS WHERE USER_ID = :uid",
            {"uid": user_id},
        )
        return cur.fetchone() is not None
    except Exception as e:
        print(f"  ❌ 회원 확인 중 오류 → {str(e)}")
        return False
    finally:
        cur.close()


def _admin_prompt_user_id_if_exists(conn):
    """
    대상 USER_ID 를 입력받고 DB에 존재하는지 확인합니다.
    - cursor.fetchone() 이 None 이면 '존재하지 않는 회원입니다' 출력 후 None 반환
    - 호출부에서는 None 이면 return / continue 로 admin_menu 루프로 돌아갑니다.
    """
    raw = input("  대상 USER_ID (숫자): ").strip()
    if not raw.isdigit():
        print("  ❌ 숫자 USER_ID를 입력하세요.")
        return None
    uid = int(raw)
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT USER_ID FROM USERS WHERE USER_ID = :uid",
            {"uid": uid},
        )
        if cur.fetchone() is None:
            print("  존재하지 않는 회원입니다.")
            return None
    except Exception as e:
        print(f"  ❌ 회원 확인 중 오류 → {str(e)}")
        return None
    finally:
        cur.close()
    return uid


# ──────────────────────────────────────────────────────────────────────────
# 관리자 전용 메뉴 (ROLE == ADMIN)
# ──────────────────────────────────────────────────────────────────────────

def admin_menu(conn, admin_user):
    """
    관리자 로그인 후 화면.
    - 회원/계좌/거래 조회, 의심거래, 강제차단, 감사로그, 회원 삭제·복구
    """
    while True:
        print("\n=== [ 관리자 메뉴 ] ===")
        print("  1. 전체 회원 조회")
        print("  2. 회원 검색")
        print("  3. 전체 계좌 조회")
        print("  4. 전체 거래내역 조회")
        print("  5. 의심 거래 조회")
        print("  6. 거래 강제 차단")
        print("  7. 감사로그 조회")
        print("  8. 회원 삭제(소프트) / 복구")
        print("  0. 로그아웃")
        print("-" * 40)

        choice = input("  메뉴 선택: ").strip()

        if choice == "1":
            admin_list_users(conn)

        elif choice == "2":
            # 숫자만 입력한 경우 USER_ID 로 간주 → DB 존재 여부 먼저 확인 후 검색
            raw = input("  검색어 (USER_ID 숫자 또는 이름): ").strip()
            if not raw:
                print("  ❌ 검색어를 입력하세요.")
                continue
            if raw.isdigit():
                if not _admin_user_id_exists(conn, int(raw)):
                    print("  존재하지 않는 회원입니다.")
                    continue
            admin_search_user(conn, raw_query=raw)

        elif choice == "3":
            admin_list_all_accounts(conn)

        elif choice == "4":
            admin_list_all_transactions(conn)

        elif choice == "5":
            admin_list_suspicious_transactions(conn)

        elif choice == "6":
            admin_block_transaction(conn, admin_user)

        elif choice == "7":
            admin_list_audit_logs(conn)

        elif choice == "8":
            # 삭제·복구 전에 USER_ID 가 USERS 에 존재하는지 main 에서 먼저 확인
            print("\n  [ 서브메뉴 ]  1) 삭제(소프트)  2) 복구  0) 취소")
            sub = input("  선택: ").strip()
            if sub == "0":
                print("  취소되었습니다.")
                continue
            if sub not in ("1", "2"):
                print("  ❌ 잘못된 선택입니다.")
                continue
            target_uid = _admin_prompt_user_id_if_exists(conn)
            if target_uid is None:
                continue
            if sub == "1":
                admin_soft_delete_user(conn, admin_user, target_uid=target_uid)
            else:
                admin_restore_user(conn, admin_user, target_uid=target_uid)

        elif choice == "0":
            print(f"\n  👋 관리자 {admin_user['name']} 님, 로그아웃합니다.")
            break

        else:
            print("  ❌ 잘못된 입력입니다. 다시 선택해주세요.")


# ──────────────────────────────────────────────────────────────────────────
# 프로그램 진입점
# ──────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("  Oracle DB에 접속 중...")
    conn = get_connection()

    if conn is None:
        print("  프로그램을 종료합니다.")
        sys.exit(1)

    print("  ✅ DB 접속 성공!")

    # 기본 관리자(admin/1234) 없으면 생성 (중복 시 스킵)
    seed_admin(conn)

    try:
        main_menu(conn)
    finally:
        conn.close()   # 프로그램 종료 시 반드시 연결 해제
        print("  DB 연결이 종료되었습니다.")

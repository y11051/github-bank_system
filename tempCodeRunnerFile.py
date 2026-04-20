"""
안전한 AI 은행 시스템 - 메인 실행 파일
========================================
실행 전 필수 설치:
    pip install cx_Oracle

Oracle Instant Client 경로도 시스템에 맞게 설정하세요.
아래 cx_Oracle.init_oracle_client() 주석 참고.
"""

import oracledb
import sys

# ── 모듈 임포트 ────────────────────────────────────────────────────────────
from auth        import register, login
from account     import register_account, check_balance
from transaction import TransactionManager

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
        print("  0. 종료")
        print("-" * 40)

        choice = input("  메뉴를 선택하세요: ").strip()

        if choice == "1":
            register(conn)

        elif choice == "2":
            user = login(conn)
            if user:
                user_menu(conn, user)   # 로그인 성공 시 회원 메뉴로 진입

        elif choice == "0":
            print("\n  시스템을 종료합니다. 감사합니다!")
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

    try:
        main_menu(conn)
    finally:
        conn.close()   # 프로그램 종료 시 반드시 연결 해제
        print("  DB 연결이 종료되었습니다.")

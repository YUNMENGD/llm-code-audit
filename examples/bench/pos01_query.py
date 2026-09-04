"""订单查询服务（含 1 处缺陷）。"""
import sqlite3


def find_order(order_no, conn: sqlite3.Connection):
    # EXPECT: CWE-89
    sql = "SELECT * FROM orders WHERE order_no = '%s'" % order_no
    return conn.execute(sql).fetchall()

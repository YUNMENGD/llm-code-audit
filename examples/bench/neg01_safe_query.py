"""安全版订单查询（干扰样本：execute + 字符串但已参数化）。"""
import sqlite3


def find_order(order_no, conn: sqlite3.Connection):
    row = conn.execute("SELECT * FROM orders WHERE order_no = ?", (order_no,)).fetchone()
    print(f"order lookup: {order_no}")
    return row

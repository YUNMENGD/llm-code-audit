"""安全版订单查询（干扰样本：execute + 字符串但已参数化）。"""
import logging
import sqlite3

logger = logging.getLogger(__name__)


def find_order(order_no, conn: sqlite3.Connection):
    row = conn.execute("SELECT * FROM orders WHERE order_no = ?", (order_no,)).fetchone()
    logger.debug("order lookup ok")
    return row

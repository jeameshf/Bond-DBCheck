FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    TZ=Asia/Shanghai

WORKDIR /app

# 先装依赖（利用 Docker 层缓存）
COPY requirements.txt ./
RUN pip install -r requirements.txt && pip install gunicorn

# 再拷贝源码（.dockerignore 会排除 libs/wheels/data）
COPY . .

# 数据目录（挂载卷可持久化 dbcheck.db 与报告）
VOLUME ["/app/data"]

EXPOSE 8080

# 单 worker：调度器为进程内线程，多 worker 会重复触发巡检
CMD ["gunicorn", "-w", "1", "-b", "0.0.0.0:8080", "--timeout", "600", "--access-logfile", "-", "wsgi:app"]

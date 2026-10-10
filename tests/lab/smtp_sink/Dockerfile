FROM python:3.12-slim-bookworm
RUN pip install --no-cache-dir aiosmtpd
COPY tests/lab/smtp_sink/sink.py /sink.py
CMD ["python", "/sink.py"]

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN useradd -m -u 10003 decoy
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# throwaway host key baked into the image (decoy only, no real credentials anywhere)
RUN python -c "import asyncssh;asyncssh.generate_private_key('ssh-rsa',key_size=2048).write_private_key('/app/host_key')" && chmod 644 /app/host_key
USER decoy
EXPOSE 2222
CMD ["python", "server.py"]

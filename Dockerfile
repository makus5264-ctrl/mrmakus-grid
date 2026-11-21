FROM python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends nmap curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . /app
ENV ZERO24_ENGINE=/app/skills/makus-autopwn/scripts/auto_pwn.py
ENV PYTHONUNBUFFERED=1
EXPOSE 9099
CMD ["python", "vps_agent.py", "--port", "9099", "--interval", "900"]

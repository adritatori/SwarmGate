# The lab container: Python + our code, running as a normal (non-root) user.
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY oor ./oor
COPY tests ./tests
RUN useradd -m lab && mkdir -p /app/results && chown -R lab /app
USER lab
ENV PYTHONDONTWRITEBYTECODE=1
CMD ["python", "-m", "oor.run", "--seeds", "10"]

FROM python:3.10

WORKDIR /app

COPY . .

RUN pip install pyre-check

CMD ["python", "run-analysis.py"]


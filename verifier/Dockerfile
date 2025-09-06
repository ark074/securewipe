FROM python:3.11-slim
WORKDIR /app
COPY verifier /app/verifier
WORKDIR /app/verifier
RUN pip install -r requirements.txt
EXPOSE 5000
ENV FLASK_APP=app
CMD ["flask","run","--host=0.0.0.0","--port=5000"]

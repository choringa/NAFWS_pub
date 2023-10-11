FROM python:3-slim
LABEL version="1.0.1" \
      name="NAFWS" \
      author="David Arteaga --> d.arteaga28@gmail.com" \
      description="Not A Fancy Web Service --> A simple python WS for security demos/testing"
#FROM ubuntu:latest

RUN apt update -y

WORKDIR /app
COPY . .
#RUN python3 -m pip install -r requierements.txt
#o
RUN pip3 install -r requirements.txt

#Caso 2.2
#RUN python3 -m pip install flask
#o
#RUN pip3 install flask

EXPOSE 5000
#nohup bash -c "exec python tester.py > /proc/1/fd/1"
#nohup python3 nafws.py 2>&1 &
CMD ["python3","nafws.py"]
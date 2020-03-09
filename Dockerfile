FROM alpine:3
COPY setup-new-aws-user /
ENTRYPOINT [ "./setup-new-aws-user" ]

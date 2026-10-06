# PandaAuth.Server 镜像（IDP 核心；开发绑定 localhost:9004，生产端口由部署 env ASPNETCORE_URLS 注入，t0000 现网 10001）
#
# 跨仓构建：Server 通过相对路径引用 panda-auth-share，因此构建上下文必须是
# panda-auth 工作区根（五个仓库同级克隆）：
#   docker build -f panda-auth-server/Dockerfile .
# 上下文过滤走同目录的 Dockerfile.dockerignore（BuildKit 按 Dockerfile 名取用，
# 模式相对上下文根=工作区根）：本仓 .dockerignore 对父上下文不生效，此前 bin/obj
# 会整体进入上下文，让构建结果随构建机本地状态漂移。

# ================= 构建阶段 =================
# 基础镜像 digest 钉值，原 tag：mcr.microsoft.com/dotnet/sdk:10.0（2026-10-06 解析）
FROM mcr.microsoft.com/dotnet/sdk@sha256:0eeb52c76e35a5431ca707ad2bc75e38006a05393045d8532ae44c15d9474523 AS build
WORKDIR /src

# restore 缓存层：先只进清单文件（slnx/global.json/props + 本仓全部 csproj + share 的
# props 与被引用的 share/src csproj），NuGet 还原只随这些文件变化，日常源码改动
# 直接命中缓存层，不再重跑 restore。csproj 覆盖 slnx 全部三工程（src/samples/tests，
# samples 无 ProjectReference）与引用图上的 panda-auth-share/src。
COPY panda-auth-server/PandaAuth.Server.slnx \
     panda-auth-server/global.json \
     panda-auth-server/Directory.Build.props \
     panda-auth-server/Directory.Packages.props \
     panda-auth-server/
COPY panda-auth-server/src/PandaAuth.Server/PandaAuth.Server.csproj panda-auth-server/src/PandaAuth.Server/
COPY panda-auth-server/samples/PandaAuth.DemoClient/PandaAuth.DemoClient.csproj panda-auth-server/samples/PandaAuth.DemoClient/
COPY panda-auth-server/tests/PandaAuth.Tests/PandaAuth.Tests.csproj panda-auth-server/tests/PandaAuth.Tests/
COPY panda-auth-share/Directory.Build.props panda-auth-share/
COPY panda-auth-share/src/PandaAuth.Shared/PandaAuth.Shared.csproj panda-auth-share/src/PandaAuth.Shared/
RUN dotnet restore panda-auth-server/PandaAuth.Server.slnx

# 全量源码层：bin/obj 已被 Dockerfile.dockerignore 挡在上下文外，restore 生成的
# obj/project.assets.json 不会被宿主产物覆盖，publish --no-restore 直接复用。
COPY panda-auth-share/ panda-auth-share/
COPY panda-auth-server/ panda-auth-server/
RUN dotnet publish panda-auth-server/src/PandaAuth.Server -c Release -o /app --no-restore --nologo

# ================= 运行阶段 =================
# 基础镜像 digest 钉值，原 tag：mcr.microsoft.com/dotnet/aspnet:10.0（2026-10-06 解析）
FROM mcr.microsoft.com/dotnet/aspnet@sha256:0fa044f682cb7d93a5a90401a00c626c66f7b00b86922be9441f869eae039f80 AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app

# 非 root 运行：aspnet 基础镜像自带 uid 1654 的 app 用户
COPY --chown=app:app --from=build /app .

# DataProtection 密钥目录必须在镜像里预建并归 app 所有：命名卷首次创建时继承的是镜像内
# 该路径的属主，目录缺失或属 root 时 app 写不进密钥，启动即失败（compose 挂载了本路径）。
RUN mkdir -p /var/lib/panda-auth/dataprotection \
    && chown app:app /var/lib/panda-auth/dataprotection

# 只绑定回环地址，公网流量一律经宿主机 Caddy 反代（禁止 0.0.0.0 裸暴露）
ENV ASPNETCORE_ENVIRONMENT=Production \
    ASPNETCORE_URLS=http://127.0.0.1:9004

EXPOSE 9004

# 镜像级探活（**仅在裸 docker run 下生效**）：deploy/docker-compose.yml 给每个服务都写了
# 容器级 healthcheck，容器级优先、会**覆盖**本指令（已实测）。两处 URL 与参数刻意同构；
# server 与此处连 start-period 都是 30s。
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -fsS http://127.0.0.1:9004/healthz || exit 1

USER app

ENTRYPOINT ["dotnet", "PandaAuth.Server.dll"]

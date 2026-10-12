# Render用・簡易Webプロキシ

中央のURL入力欄から公開Webサイトを開く、Node.js + Express製の簡易プロキシです。HTML/CSS内の一般的なリンクや画像・スタイルシートのURLを書き換え、可能な範囲でプロキシ経由にします。

## Renderへのデプロイ方法

1. このフォルダーの中身をGitHubリポジトリにアップロードします。
2. Renderで **New → Web Service** を選び、そのリポジトリを接続します。
3. Runtimeは **Node**、Build Commandは `npm install`、Start Commandは `npm start` にします。Render Blueprintを使う場合は、同梱の `render.yaml` の設定を利用できます。
4. デプロイが終わると、Renderが発行したURLで開けます。

## ローカルで実行する場合

```bash
npm install
npm start
```

その後 `http://localhost:10000` を開きます。

## 制限と安全対策

- 完全なブラウザー型プロキシではありません。ログイン、認証Cookie、POSTフォーム、WebSocket、動画、複雑なJavaScriptを利用するサイトでは正常に動かないことがあります。
- HTTP/HTTPSのみ対応し、標準のWebポート（80/443）以外は拒否します。
- DNS接続時にプライベートIP、ループバック、リンクローカル、その他の特殊用途IPを拒否します。
- 1分あたりのアクセス回数を制限し、取得するレスポンスは最大8MBです。
- 公開プロキシは第三者に利用される可能性があります。広く公開する場合は、認証や追加の不正利用対策を検討してください。パスワードや個人情報は入力しないでください。

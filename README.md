# Weekly Intune Status Report

> Microsoft Intune と Microsoft Defender for Endpoint のデータを週次で収集・分析し、デバイス管理状況をまとめた HTML メールレポートを自動送信する Security Copilot Agent ソリューション。

## 概要

`WeeklyIntuneStatusReport` は、Microsoft Security Copilot の Standard Agent として動作し、以下を自動化します。

- Intune 管理対象デバイスのインベントリ収集（OS 別・コンプライアンス状態別）
- デバイス登録数の先週比トレンド分析
- コンプライアンスポリシー・構成プロファイルの適用状況把握
- 管理対象アプリのインストール成功/失敗状況
- Defender TVM による未修正 CVE ベースのパッチ遅延デバイス特定
- MDAV（Windows Defender）/ MDE（Defender for Endpoint）のバージョン分布分析
- 全データを統合した傾向分析・推奨対策の生成
- メール互換（全インラインスタイル）の HTML レポートを Logic App 経由で送信

| 項目 | 値 |
|---|---|
| **プラグイン名** | `WeeklyIntuneStatusReport` |
| **形式** | Agent (gpt-4.1) + KQL (Defender TVM) + LogicApp |
| **実行周期** | 毎週（604,800 秒 = 7日間） |
| **レポート言語** | 日本語 |
| **メール送信** | Azure Logic App (Office 365 コネクタ) |

## アーキテクチャ

```
┌──────────────────────────────┐
│ Microsoft Security Copilot   │
│ Standard Agent               │
│ WeeklyIntuneStatusReport     │
└──────────────┬───────────────┘
               │  (逐次呼び出し)
               │
               ├──▶ Intune プラグイン (組み込み)
               │     - GetIntuneDevices
               │     - GetCompliancePolicies
               │     - GetConfigurationProfiles
               │     - GetManagedApps
               │
               ├──▶ Defender KQL (Advanced Hunting)
               │     - DeviceTvmSoftwareVulnerabilities → パッチ遅延
               │     - DeviceTvmSoftwareInventory      → MDAV/MDE バージョン
               │
               └──▶ Azure Logic App
                     - Office 365 メール送信
```

## レポート内容（10 セクション）

| # | セクション | 内容 | データソース |
|---|---|---|---|
| 1 | **サマリーカード** | 総デバイス数・準拠率・エラー数・パッチ遅延数（先週比） | Intune |
| 2 | **全体傾向分析・推奨対策** | デバイス管理全体の傾向要約、要注意ポイント（非準拠/パッチ遅延/MDAV-MDE 乖離/ポリシーエラー/アプリ失敗）、優先度付き推奨対策テーブル | 全データ統合 |
| 3 | **OS 別アセット一覧** | Windows / iOS / Android / macOS 別デバイス数と比率 | Intune |
| 4 | **デバイス登録状況** | 今週の新規登録デバイスと先週比較 | Intune |
| 5 | **エラー・非準拠デバイス** | コンプライアンス状態別サマリーと非準拠デバイス一覧 | Intune |
| 6 | **アプリサマリー** | 管理アプリの状態別件数（インストール済み/失敗/保留） | Intune |
| 7 | **ポリシー状況** | 構成プロファイル・コンプライアンスポリシーの適用状況 | Intune |
| 8 | **コンプライアンス状態** | 全デバイスの準拠状態分布（色分けテーブル） | Intune |
| 9 | **パッチ遅延デバイス** | 未修正 OS CVE が 10 件以上のデバイス一覧 | Defender TVM |
| 10 | **Defender バージョン** | MDAV / MDE ソフトウェアバージョン分布 | Defender TVM |

## ファイル構成

```
WeeklyIntuneStatusReport/
├── WeeklyIntuneStatusReport.yaml              # プラグインマニフェスト (YAML)
├── WeeklyIntuneStatusReport_card.html         # プラグインカード (ビジュアルサマリー)
├── WeeklyIntuneStatusReport_LogicApp_ARM.json # Logic App ARM テンプレート
└── README.md                                   # このファイル
```

## スキル構成

### Agent スキル（オーケストレーション）

| スキル名 | モデル | 説明 |
|---|---|---|
| `OrchestrateWeeklyIntuneReport` | gpt-4.1 | 全フェーズのオーケストレーション（データ収集→分析→HTML 生成→メール送信） |

### KQL スキル（Defender TVM）

| スキル名 | テーブル | フィルタ条件 | 説明 |
|---|---|---|---|
| `GetWindowsPatchLagDevices` | `DeviceTvmSoftwareVulnerabilities` | `PendingCveCount >= 10` | 未修正 CVE が 10 件以上の Windows デバイスを特定 |
| `GetMDAVEngineVersions` | `DeviceTvmSoftwareInventory` | `SoftwareName == "windows_defender"` | MDAV バージョン分布を集計 |
| `GetMDEClientVersions` | `DeviceTvmSoftwareInventory` | `SoftwareName == "defender_for_endpoint"` | MDE バージョン分布を集計 |

> **注意**: `SoftwareName` は環境によって異なる場合があります。以下のクエリで確認できます:
> ```kql
> DeviceTvmSoftwareInventory
> | where OSPlatform startswith_cs "Windows"
> | where SoftwareName has "defender"
> | distinct SoftwareName
> ```

### Intune プラグインスキル（組み込み）

| スキル名 | 説明 |
|---|---|
| `GetIntuneDevices` | 全管理対象デバイス（OS・準拠状態・登録日時）を取得 |
| `GetCompliancePolicies` | コンプライアンスポリシーと準拠状況サマリーを取得 |
| `GetConfigurationProfiles` | 構成プロファイルと適用状況（成功/エラー/競合）を取得 |
| `GetManagedApps` | 管理対象アプリのインストール状態サマリーを取得 |

> **注意**: 上記の Intune スキル名は一般的な名称です。実際の環境で利用可能なスキル名は Security Copilot の**プラグイン管理**画面で確認してください。

### LogicApp スキル

| スキル名 | 説明 |
|---|---|
| `SendWeeklyIntuneReportEmail` | 生成した HTML レポートを Logic App 経由でメール送信 |

## 前提条件

### 1. Security Copilot

- **Intune プラグイン**が有効化されていること
- **Microsoft Defender for Endpoint** が接続されていること（TVM テーブルへのアクセスに必要）

### 2. Azure Logic App

付属の ARM テンプレートでメール送信用 Logic App をデプロイしてください:

```bash
az deployment group create \
  --resource-group <リソースグループ名> \
  --template-file WeeklyIntuneStatusReport_LogicApp_ARM.json \
  --parameters emailAddress="recipient@your-domain.com"
```

デプロイ後、Azure ポータルで Office 365 接続の認証（サインイン）を行ってください。

Logic App の HTTP トリガーが受け付ける JSON スキーマ:

```json
{
  "type": "object",
  "properties": {
    "ReportHtml": {
      "type": "string"
    }
  },
  "required": ["ReportHtml"]
}
```

## デプロイ手順

1. **Logic App をデプロイ**（上記コマンドを実行）
2. **Azure ポータル**で Office 365 Outlook 接続を認証
3. **`WeeklyIntuneStatusReport.yaml`** を Security Copilot にカスタムプラグインとしてアップロード
4. **プラグイン設定**で以下の 3 項目を入力して保存:

   | 設定名 | 説明 | 例 |
   |---|---|---|
   | `LogicAppSubscriptionId` | Logic App のサブスクリプション ID | `00000000-0000-0000-0000-000000000000` |
   | `LogicAppResourceGroup` | Logic App のリソースグループ名 | `rg-securitycopilot` |
   | `LogicAppWorkflowName` | Logic App のワークフロー名 | `PluginLogicApp_WeeklyIntuneReport` |

5. エージェントの初回実行をトリガー（手動または次回 WeeklySchedule まで待機）

## カスタマイズ

### 実行周期の変更

`DefaultPollPeriodSeconds: 604800`（7日）を変更:
- 毎日: `86400`
- 2週間ごと: `1209600`

### パッチ遅延の閾値変更

`GetWindowsPatchLagDevices` の `PendingCveCount >= 10` を変更（例: `>= 5` でより厳しく）

### レポート言語の変更

Instructions 内の `All report text must be written in Japanese.` を変更

## 技術的な注意事項

### HTML レポートのメール互換性

| 要件 | 理由 |
|---|---|
| 全インラインスタイル (`style="..."`) | メールクライアントは `<style>` タグを無視する |
| `<table>` ベースレイアウト | flexbox/grid はメールで非対応 |
| `max-width: 680px` | メール表示に最適化 |
| JavaScript/画像不使用 | メールでブロックされる |
| HTML サイズ 30KB 以下 | モデル出力トークン枠の制約 |

### KQL クエリの注意点

| ポイント | 詳細 |
|---|---|
| TVM テーブルはスナップショット | `Timestamp` フィルタ不要 |
| `OSPlatform` フィルタ | `startswith_cs "Windows"` を使用（`has` だと環境によりマッチしない） |

### エージェント実行の制約

| ルール | 理由 |
|---|---|
| スキルは逐次呼び出し | 並列呼び出しで tool_call チェーン破損を防止 |
| 各テーブル最大 10 行 | HTML 30KB 制限を遵守 |
| 失敗時はスキップ | エラーで全体が止まらないようにする |

## 関連ソリューション

| ソリューション | 説明 |
|---|---|
| [WeeklyDefenderIncidentReport](../WeeklyDefenderIncidentReport/) | Defender インシデントの週次レポート |
| [WeeklyThreatIntelReport](../WeeklyThreatIntelReport/) | MDTI 脅威インテリジェンスの週次レポート |
| [WeeklyEntraIdRiskUserAnalyticsReport](../WeeklyEntraIdRiskUserAnalyticsReport/) | Entra ID リスクユーザーの週次レポート |
| [CVEImpactInvestigator](../CVEImpactInvestigator/) | CVE 影響調査エージェント |

## ライセンス

MIT

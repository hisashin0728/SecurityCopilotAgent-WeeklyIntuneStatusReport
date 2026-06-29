# Weekly Intune Status Report

> Microsoft Intune と Microsoft Defender for Endpoint のデータを週次で収集・分析し、デバイス管理状況をまとめた HTML メールレポートを自動送信する Security Copilot Agent ソリューション。

## 概要

`WeeklyIntuneStatusReport` は、Microsoft Security Copilot の Standard Agent として動作し、以下を自動化します。

- Defender Advanced Hunting (DeviceInfo) を KQL で集計したデバイスインベントリ（OS 別・総数）
- デバイス登録数の先週比トレンド分析（DeviceInfo 初観測日近似）
- 重複デバイス検出（同一デバイス名で複数 DeviceId）
- Defender TVM による未修正 CVE ベースのパッチ遅延デバイス特定
- MDAV（Windows Defender）/ MDE（Defender for Endpoint）のバージョン分布分析
- 全データを統合した傾向分析・推奨対策の生成
- メール互換（全インラインスタイル）の HTML レポートを Logic App 経由で送信

> **大規模対応**: デバイス情報は全件取得せず KQL 側で集計するため、1万台規模でもトークン超過なく安定動作します。コンプライアンスは GetIntuneDevices を「非準拠のみ」で 1 回だけ呼び出して近似準拠率を補完します。

| 項目 | 値 |
|---|---|
| **プラグイン名** | `WeeklyIntuneStatusReport` |
| **バージョン** | v1.5.0 |
| **形式** | Agent (gpt-4.1) + KQL (Defender DeviceInfo/TVM) + Intune + LogicApp |
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
               ├──▶ Defender KQL (Advanced Hunting)
               │     - DeviceInfo                       → 総数/OS内訳/重複/登録トレンド
               │     - DeviceTvmSoftwareVulnerabilities → パッチ遅延
               │     - DeviceTvmSoftwareInventory      → MDAV/MDE バージョン
               │
               ├──▶ Intune プラグイン (組み込み)
               │     - GetIntuneDevices (非準拠のみ少量取得→近似準拠率)
               │
               └──▶ Azure Logic App
                     - Office 365 メール送信
```

## レポート内容（9 セクション）

| # | セクション | 内容 | データソース |
|---|---|---|---|
| 1 | **サマリーカード** | 総デバイス数・今週新規数（先週比）・重複デバイス数・パッチ遅延数 | DeviceInfo / TVM |
| 2 | **全体傾向分析・推奨対策** | デバイス管理全体の傾向要約、要注意ポイント（パッチ遅延/MDAV-MDE 乖離/重複デバイス）、優先度付き推奨対策テーブル | 全データ統合 |
| 3 | **OS 別アセット一覧** | OS / OS バージョン別デバイス数と比率 | DeviceInfo |
| 4 | **デバイス登録状況** | 今週/先週/それ以前の新規デバイス数（初観測日近似） | DeviceInfo |
| 5 | **エラー・非準拠デバイス** | 非準拠デバイス一覧 | Intune（Noncompliant） |
| 8 | **コンプライアンス状態** | 近似準拠率（(総数−非準拠)/総数）と Compliant/NonCompliant 分布 | DeviceInfo + Intune |
| 9 | **パッチ遅延デバイス** | 未修正 OS CVE が 10 件以上のデバイス一覧 | Defender TVM |
| 10 | **重複デバイスオブジェクト** | 同一デバイス名で複数 DeviceId が存在するグループ一覧 | DeviceInfo |
| 11 | **Defender バージョン** | MDAV / MDE ソフトウェアバージョン分布 | Defender TVM |

## ファイル構成

```
WeeklyIntuneStatusReport/
├── WeeklyIntuneStatusReport.yaml              # プラグインマニフェスト (YAML)
├── WeeklyIntuneStatusReport_card.html         # プラグインカード (ビジュアルサマリー)
├── WeeklyIntuneStatusReport_LogicApp_ARM.json # Logic App ARM テンプレート
└── README.md                                   # このファイル
```

> **デバイスインベントリ（総数/OS/重複/登録トレンド）はすべて KQL で集計するため、Intune プラグイン非依存です。**

## スキル構成

### Agent スキル（オーケストレーション）

| スキル名 | モデル | 説明 |
|---|---|---|
| `OrchestrateWeeklyIntuneReport` | gpt-4.1 | 全フェーズのオーケストレーション（データ収集→分析→HTML 生成→メール送信） |

### KQL スキル（Defender TVM）

| スキル名 | テーブル | フィルタ条件 | 説明 |
|---|---|---|---|
| `GetDeviceInventorySummary` | `DeviceInfo` | 直近7日 / DeviceId 単位最新 | 総数・OS/OS バージョン別台数を集計 |
| `GetDuplicateDevices` | `DeviceInfo` | `ObjectCount > 1` | 同一デバイス名で複数 DeviceId の重複候補を集計 |
| `GetDeviceEnrollmentTrend` | `DeviceInfo` | 初観測日近似 | 今週/先週/それ以前の新規デバイス数 |
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

> **注意**: コンプライアンス（非準拠）は GetIntuneDevices を ComplianceState=Noncompliant で 1 回だけ呼び出し補完する。

### Intune プラグインスキル（組み込み・ハイブリッド補完）

| スキル名 | 呼び出し条件 | 説明 |
|---|---|---|
| `GetIntuneDevices` | `ComplianceState=Noncompliant`（User/Device 不指定）1 回のみ | 非準拠デバイスのみ少量取得。総数（Phase 1 KQL 集計）から近似準拠率を算出 |

### LogicApp スキル

| スキル名 | 説明 |
|---|---|
| `SendWeeklyIntuneReportEmail` | 生成した HTML レポートを Logic App 経由でメール送信 |

## 前提条件

### 1. Security Copilot

- **Microsoft Defender for Endpoint** が接続されていること（DeviceInfo / TVM テーブルへのアクセスに必要）
- **Intune プラグイン**が有効化されていること（非準拠デバイス補完取得 GetIntuneDevices に必要）

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
| HTML 全体 30KB 以下 | モデル出力トークン枠の制約 |
| 失敗時はスキップ | エラーで全体が止まらないようにする |
| 重複デバイス検出は KQL で集計 | DeviceInfo を DeviceName 重複で集計しトークンを抑制 |

## 関連ソリューション

| ソリューション | 説明 |
|---|---|
| [WeeklyDefenderIncidentReport](../WeeklyDefenderIncidentReport/) | Defender インシデントの週次レポート |
| [WeeklyThreatIntelReport](../WeeklyThreatIntelReport/) | MDTI 脅威インテリジェンスの週次レポート |
| [WeeklyEntraIdRiskUserAnalyticsReport](../WeeklyEntraIdRiskUserAnalyticsReport/) | Entra ID リスクユーザーの週次レポート |
| [CVEImpactInvestigator](../CVEImpactInvestigator/) | CVE 影響調査エージェント |

## 版歴（Change Log）

| バージョン | 日付 | 変更内容 |
|---|---|---|
| **v1.0.0** | 2026-06-10 | 初版リリース（Intune 組み込みスキル + Defender TVM KQL + Logic App メール送信。11 セクション HTML レポート） |
| **v1.1.0** | 2026-06-17 | `GetIntuneDevices` が単一デバイス詳細を返す不具合に対応。Phase 1 で User / Device パラメータを設定しないことを明示し、存在しない `Request` 入力を廃止。全件取得のため Platform 別（Windows / iOS / Android / macOS）の分割呼び出しに変更 |
| **v1.2.0** | 2026-06-29 | 実在しない Intune スキル `GetCompliancePolicies` / `GetConfigurationProfiles` / `GetManagedApps` を削除（取得不可の原因）。コンプライアンス状態・重複・プライマリユーザー不在は `GetIntuneDevices` 集計に一本化。アプリ（セクション6）・ポリシー（セクション7）は組織横断スキル未提供のため「取得不可」明記に変更 |
| **v1.3.0** | 2026-07-06 | 1万台規模でのトークン超過回避のため `GetIntuneDevices` 全件取得を廃止し、DeviceInfo を KQL 集計する方式に移行。KQL スキル `GetDeviceInventorySummary` / `GetDuplicateDevices` / `GetDeviceEnrollmentTrend` を追加。コンプライアンス/UPN/ポリシー/アプリは Defender AH データソース未提供のため取得不可明記。RequiredSkillsets から Intune を除外 |
| **v1.4.0** | 2026-07-13 | ハイブリッド追加: `GetIntuneDevices` を ComplianceState=Noncompliant で 1 回だけ呼び出し、非準拠デバイスを少量補完。近似準拠率=(総数−非準拠)/総数。セクション 5/8 とサマリーカードにコンプライアンスを復活。RequiredSkillsets に Intune を再追加（プライマリユーザー不在は取得不可のまま） |
| **v1.5.0** | 2026-07-20 | 取得不可表示となるセクションをレポートから削除: プライマリユーザー不在（5-1）・管理アプリサマリー（6）・Intune ポリシー状況（7）を廃止 |

## ライセンス

MIT

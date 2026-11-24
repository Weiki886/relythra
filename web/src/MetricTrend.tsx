import { useEffect, useRef } from "react";
import type { EChartsOption } from "echarts";
import { use as registerEChartsModules } from "echarts/core";
import { LineChart } from "echarts/charts";
import {
  AriaComponent,
  GridComponent,
  LegendComponent,
  TooltipComponent,
} from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import * as echarts from "echarts/core";
import type { MetricTrend as MetricTrendData } from "./investigation";

registerEChartsModules([
  LineChart,
  AriaComponent,
  GridComponent,
  LegendComponent,
  TooltipComponent,
  CanvasRenderer,
]);

const palette = ["#147d64", "#246c9c", "#b76727", "#914766", "#667d2c"];

function formatAxis(timestamp: number) {
  return new Date(timestamp).toISOString().slice(5, 16).replace("T", " ");
}

export default function MetricTrend({
  trend,
  completeness,
}: {
  trend: MetricTrendData;
  completeness: string;
}) {
  const chartElement = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const element = chartElement.current;
    if (!element || typeof window.CanvasRenderingContext2D === "undefined")
      return;

    const chart = echarts.init(element, null, { renderer: "canvas" });
    const option: EChartsOption = {
      animation: false,
      aria: { enabled: true, decal: { show: true } },
      color: palette,
      grid: { left: 58, right: 20, top: 26, bottom: 56 },
      legend: { type: "scroll", bottom: 4, left: 56, right: 16 },
      tooltip: {
        trigger: "axis",
        renderMode: "richText",
        valueFormatter: (value) => `${value} ${trend.unit}`,
      },
      xAxis: {
        type: "time",
        name: "UTC",
        axisLabel: {
          formatter: (value) => formatAxis(Number(value)),
          hideOverlap: true,
        },
      },
      yAxis: {
        type: "value",
        name: trend.unit,
        scale: true,
        axisLabel: { hideOverlap: true },
      },
      series: trend.series.map((line) => ({
        name: line.name,
        type: "line",
        showSymbol: line.samples.length < 2,
        connectNulls: false,
        data: line.samples.map((sample) => [sample.timestamp, sample.value]),
      })),
    };
    chart.setOption(option);

    const resize = () => chart.resize();
    if (typeof ResizeObserver !== "undefined") {
      const observer = new ResizeObserver(resize);
      observer.observe(element);
      return () => {
        observer.disconnect();
        chart.dispose();
      };
    }
    window.addEventListener("resize", resize);
    return () => {
      window.removeEventListener("resize", resize);
      chart.dispose();
    };
  }, [trend]);

  const sampleCount = trend.series.reduce(
    (count, line) => count + line.samples.length,
    0,
  );

  return (
    <section className="metric-trend" aria-labelledby="metric-trend-heading">
      <div className="section-heading">
        <h3 id="metric-trend-heading">指标趋势</h3>
        <span className={`badge ${completeness === "COMPLETE" ? "" : "warning"}`}>
          {completeness}
        </span>
      </div>
      <p className="muted metric-trend-meta">
        {trend.series.length} 条序列 · {sampleCount} 个样本 · 单位：{trend.unit} · 横轴：UTC
      </p>
      <div
        ref={chartElement}
        className="metric-chart"
        role="img"
        aria-label="Prometheus 指标趋势图"
        aria-describedby="metric-trend-heading"
      />
      <details>
        <summary>查看序列数据（{sampleCount} 个样本）</summary>
        <div className="metric-table-scroll">
          <table className="metric-table">
            <caption>每条序列的范围摘要；完整样本保留在下方观测摘要中</caption>
            <thead>
              <tr>
                <th scope="col">序列</th>
                <th scope="col">样本数</th>
                <th scope="col">首值</th>
                <th scope="col">末值</th>
                <th scope="col">最小值</th>
                <th scope="col">最大值</th>
              </tr>
            </thead>
            <tbody>
              {trend.series.map((line) => {
                const values = line.samples.map((sample) => sample.value);
                const first = line.samples[0]?.value;
                const last = line.samples.at(-1)?.value;
                return (
                  <tr key={line.name}>
                    <th scope="row">{line.name}</th>
                    <td>{values.length}</td>
                    <td className="mono">{first ?? "未记录"}</td>
                    <td className="mono">{last ?? "未记录"}</td>
                    <td className="mono">
                      {values.length ? Math.min(...values) : "未记录"}
                    </td>
                    <td className="mono">
                      {values.length ? Math.max(...values) : "未记录"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </details>
    </section>
  );
}

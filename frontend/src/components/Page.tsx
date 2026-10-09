import type { IconName } from './Icon';
import { Icon } from './Icon';

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string;
  title: string;
  description: string;
  actions?: React.ReactNode;
}) {
  return (
    <header className="page-header">
      <div>
        <span className="eyebrow">{eyebrow}</span>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {actions ? <div className="page-header__actions">{actions}</div> : null}
    </header>
  );
}

export function MetricCard({
  label,
  value,
  detail,
  icon,
  tone = 'default',
}: {
  label: string;
  value: string | number;
  detail: string;
  icon: IconName;
  tone?: 'default' | 'danger' | 'warning' | 'accent';
}) {
  return (
    <article className={`metric-card metric-card--${tone}`}>
      <div className="metric-card__top">
        <span>{label}</span>
        <span className="metric-card__icon"><Icon name={icon} size={19} /></span>
      </div>
      <strong>{value}</strong>
      <small>{detail}</small>
    </article>
  );
}

export function Panel({
  title,
  subtitle,
  action,
  children,
  className = '',
}: {
  title: string;
  subtitle?: string;
  action?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      <div className="panel__header">
        <div>
          <h2>{title}</h2>
          {subtitle ? <p>{subtitle}</p> : null}
        </div>
        {action ? <div className="panel__action">{action}</div> : null}
      </div>
      <div className="panel__body">{children}</div>
    </section>
  );
}

export function TechniqueTag({ id }: { id: string }) {
  return <span className="technique-tag">{id}</span>;
}

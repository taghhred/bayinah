import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'

const mdComponents = {
  a: ({ href, children, ...props }) => (
    <a href={href} target="_blank" rel="noopener noreferrer" {...props}>
      {children}
    </a>
  ),
}

/**
 * Renders Gemini / server text that may contain Markdown (headings, lists, tables, code).
 */
export function MarkdownBlock({ content, className = '' }) {
  const text = typeof content === 'string' ? content : String(content ?? '')
  if (!text.trim()) {
    return null
  }
  return (
    <div className={`markdown-body ${className}`.trim()}>
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents}>
        {text}
      </ReactMarkdown>
    </div>
  )
}

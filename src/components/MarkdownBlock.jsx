import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'

const mdComponents = {
  a: ({ href, children, ...props }) => (
    <a href={href} target="_blank" rel="noopener noreferrer" {...props}>
      {children}
    </a>
  ),
}

function buildComponents(bidiAuto) {
  if (!bidiAuto) {
    return mdComponents
  }
  return {
    ...mdComponents,
    p: (props) => <p dir="auto" {...props} />,
    li: (props) => <li dir="auto" {...props} />,
    blockquote: (props) => <blockquote dir="auto" {...props} />,
    th: (props) => <th dir="auto" {...props} />,
    td: (props) => <td dir="auto" {...props} />,
    h1: (props) => <h1 dir="auto" {...props} />,
    h2: (props) => <h2 dir="auto" {...props} />,
    h3: (props) => <h3 dir="auto" {...props} />,
    h4: (props) => <h4 dir="auto" {...props} />,
    pre: (props) => (
      <pre dir="ltr" style={{ unicodeBidi: 'isolate' }} {...props} />
    ),
    code: ({ className, children, ...props }) => {
      const isFenced = Boolean(className && /language-[\w-]+/.test(String(className)))
      if (!isFenced) {
        return (
          <code
            className={className}
            dir="ltr"
            style={{ unicodeBidi: 'isolate' }}
            {...props}
          >
            {children}
          </code>
        )
      }
      return (
        <code className={className} {...props}>
          {children}
        </code>
      )
    },
  }
}

/**
 * Renders Gemini / server text that may contain Markdown (headings, lists, tables, code).
 * @param {boolean} [bidiAuto] — Use dir="auto" on blocks and isolate LTR for code (better Arabic + English in one report).
 */
export function MarkdownBlock({ content, className = '', bidiAuto = false }) {
  const text = typeof content === 'string' ? content : String(content ?? '')
  if (!text.trim()) {
    return null
  }
  const components = buildComponents(bidiAuto)
  return (
    <div className={`markdown-body ${className}`.trim()}>
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={components}>
        {text}
      </ReactMarkdown>
    </div>
  )
}

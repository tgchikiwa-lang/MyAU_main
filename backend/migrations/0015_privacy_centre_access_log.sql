-- Create table for Privacy Centre access logs and active shares
CREATE TABLE IF NOT EXISTS public.data_access_logs (
    id SERIAL PRIMARY KEY,
    student_id UUID NOT NULL,
    viewer_id UUID NOT NULL,
    resource_type TEXT NOT NULL,
    viewed_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_active BOOLEAN DEFAULT TRUE NOT NULL
);

-- Index for fast lookups by student
CREATE INDEX IF NOT EXISTS idx_data_access_logs_student_id ON public.data_access_logs(student_id);
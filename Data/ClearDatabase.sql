-- Disable foreign key constraints temporarily
EXEC sp_MSforeachtable 'ALTER TABLE ? NOCHECK CONSTRAINT ALL';

-- Clear data from all tables
TRUNCATE TABLE [dbo].[QuestionResponses];
TRUNCATE TABLE [dbo].[AssessmentResults];
TRUNCATE TABLE [dbo].[AssessmentQuestions];
TRUNCATE TABLE [dbo].[Assessments];
TRUNCATE TABLE [dbo].[CourseContents];
TRUNCATE TABLE [dbo].[StudentCourses];
TRUNCATE TABLE [dbo].[Courses];
TRUNCATE TABLE [dbo].[Users];

-- Re-enable foreign key constraints
EXEC sp_MSforeachtable 'ALTER TABLE ? CHECK CONSTRAINT ALL';

-- Reset identity columns
DBCC CHECKIDENT ('[dbo].[Users]', RESEED, 0);
DBCC CHECKIDENT ('[dbo].[Courses]', RESEED, 0);
DBCC CHECKIDENT ('[dbo].[Assessments]', RESEED, 0);
DBCC CHECKIDENT ('[dbo].[AssessmentQuestions]', RESEED, 0);
DBCC CHECKIDENT ('[dbo].[AssessmentResults]', RESEED, 0);
DBCC CHECKIDENT ('[dbo].[QuestionResponses]', RESEED, 0);
DBCC CHECKIDENT ('[dbo].[CourseContents]', RESEED, 0);
DBCC CHECKIDENT ('[dbo].[StudentCourses]', RESEED, 0); 